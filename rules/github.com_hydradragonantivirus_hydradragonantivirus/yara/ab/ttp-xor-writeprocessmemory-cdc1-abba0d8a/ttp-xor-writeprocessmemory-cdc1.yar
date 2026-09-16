rule TTP_XOR_WriteProcessMemory_cdc1 {
  strings:
    $key_cdc1 = { 9a b3 [2] a8 91 [2] ae a4 [2] 80 a4 [2] bf b8 }

  condition:
    any of them
}