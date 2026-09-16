rule TTP_XOR_WriteProcessMemory_2ef5 {
  strings:
    $key_2ef5 = { 79 87 [2] 4b a5 [2] 4d 90 [2] 63 90 [2] 5c 8c }

  condition:
    any of them
}