rule TTP_XOR_WriteProcessMemory_8fa8 {
  strings:
    $key_8fa8 = { d8 da [2] ea f8 [2] ec cd [2] c2 cd [2] fd d1 }

  condition:
    any of them
}