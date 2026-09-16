rule PEiD_02181_Symantec_WinFax_PRO_8_3_Coverpage_Quick_CoverPage_ {
  meta:
    description = "[Symantec WinFax PRO 8.3 Coverpage Quick CoverPage]"
    ep_only     = "false"

  strings:
    $a = { FF FF ?? ?? ?? ?? ?? 43 6F 76 65 72 44 61 74 61 62 61 73 65 }

  condition:
    $a
}