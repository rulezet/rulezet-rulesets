rule PSS_Agent_v6 {
  meta:
    description = "PSS Agent version 6.0.0 and 6.1.0"
    author      = "Geoffrey Alexander <geoff@citizenlab.ca>"
    date        = "2017-07-20"

  strings:
    $cmdproc = "CmdProc_" wide

    $u1 = "C:\\Windows\\temp\\KB2979214.pdb" ascii
    $u2 = { 06 1f 41 49 4d 48 50 4f 31 }

    $s1  = "Did not complete transaction with pipe server" wide
    $s2  = "SkypeControlAPIAttach" wide
    $s3  = "SkypeControlAPIDiscover" wide
    $s4  = "URL###Execute" wide
    $s5  = "Failed to AddClipboardFormatListener, error [" ascii
    $s6  = "transactionrequest.<xmlattr>" wide
    $s7  = "DC615DA9-94B5-4477-9C33-3A393BC9E63F" ascii
    $s8  = "getip.<xmlattr>.agentid" wide
    $s9  = "AVAgentInstallException@agent@@" ascii
    $s10 = "AVAgentCommandsException@agent@@" ascii
    $s11 = "AVAgentCustomerConfigException@agent@@" ascii
    $s12 = "AVTransactionParsingException@communication@@agent" ascii
    $s13 = "AVStorageException@config@agent@@" ascii
    $s14 = "AVDBStorageException@db@agent@@" ascii

    $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

  condition:
    uint16(0) == 0x5a4d and $cmdproc and $str_decrypt_loop and 1 of ($u*) and 8 of ($s*)
}