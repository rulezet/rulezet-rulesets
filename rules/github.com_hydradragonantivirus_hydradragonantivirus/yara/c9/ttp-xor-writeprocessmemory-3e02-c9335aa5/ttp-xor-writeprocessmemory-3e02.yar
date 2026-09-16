rule TTP_XOR_WriteProcessMemory_3e02 {
  strings:
    $key_3e02 = { 69 70 [2] 5b 52 [2] 5d 67 [2] 73 67 [2] 4c 7b }

  condition:
    any of them
}