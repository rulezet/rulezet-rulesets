rule TTP_XOR_WriteProcessMemory_2496 {
  strings:
    $key_2496 = { 73 e4 [2] 41 c6 [2] 47 f3 [2] 69 f3 [2] 56 ef }

  condition:
    any of them
}