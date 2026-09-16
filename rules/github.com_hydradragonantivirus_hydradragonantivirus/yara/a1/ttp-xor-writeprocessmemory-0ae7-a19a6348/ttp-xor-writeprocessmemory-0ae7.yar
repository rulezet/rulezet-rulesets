rule TTP_XOR_WriteProcessMemory_0ae7 {
  strings:
    $key_0ae7 = { 5d 95 [2] 6f b7 [2] 69 82 [2] 47 82 [2] 78 9e }

  condition:
    any of them
}