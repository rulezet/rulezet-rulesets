rule TTP_XOR_WriteProcessMemory_0a02 {
  strings:
    $key_0a02 = { 5d 70 [2] 6f 52 [2] 69 67 [2] 47 67 [2] 78 7b }

  condition:
    any of them
}