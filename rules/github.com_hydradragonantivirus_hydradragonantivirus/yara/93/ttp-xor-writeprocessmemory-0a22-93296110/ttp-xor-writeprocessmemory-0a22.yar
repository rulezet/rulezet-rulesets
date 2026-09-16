rule TTP_XOR_WriteProcessMemory_0a22 {
  strings:
    $key_0a22 = { 5d 50 [2] 6f 72 [2] 69 47 [2] 47 47 [2] 78 5b }

  condition:
    any of them
}