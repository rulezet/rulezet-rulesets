rule TTP_XOR_WriteProcessMemory_21d0 {
  strings:
    $key_21d0 = { 76 a2 [2] 44 80 [2] 42 b5 [2] 6c b5 [2] 53 a9 }

  condition:
    any of them
}