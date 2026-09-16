rule TTP_XOR_WriteProcessMemory_0a41 {
  strings:
    $key_0a41 = { 5d 33 [2] 6f 11 [2] 69 24 [2] 47 24 [2] 78 38 }

  condition:
    any of them
}