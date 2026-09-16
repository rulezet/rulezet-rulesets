rule TTP_XOR_WriteProcessMemory_2473 {
  strings:
    $key_2473 = { 73 01 [2] 41 23 [2] 47 16 [2] 69 16 [2] 56 0a }

  condition:
    any of them
}