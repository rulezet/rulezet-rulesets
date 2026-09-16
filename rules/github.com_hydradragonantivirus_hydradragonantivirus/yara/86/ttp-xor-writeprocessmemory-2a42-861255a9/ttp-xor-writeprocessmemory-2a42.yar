rule TTP_XOR_WriteProcessMemory_2a42 {
  strings:
    $key_2a42 = { 7d 30 [2] 4f 12 [2] 49 27 [2] 67 27 [2] 58 3b }

  condition:
    any of them
}