rule TTP_XOR_WriteProcessMemory_cdcc {
  strings:
    $key_cdcc = { 9a be [2] a8 9c [2] ae a9 [2] 80 a9 [2] bf b5 }

  condition:
    any of them
}