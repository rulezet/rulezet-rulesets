rule TTP_XOR_WriteProcessMemory_cdcb {
  strings:
    $key_cdcb = { 9a b9 [2] a8 9b [2] ae ae [2] 80 ae [2] bf b2 }

  condition:
    any of them
}