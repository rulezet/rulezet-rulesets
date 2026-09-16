rule TTP_XOR_WriteProcessMemory_cdcd {
  strings:
    $key_cdcd = { 9a bf [2] a8 9d [2] ae a8 [2] 80 a8 [2] bf b4 }

  condition:
    any of them
}