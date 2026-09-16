rule TTP_XOR_WriteProcessMemory_5ae7 {
  strings:
    $key_5ae7 = { 0d 95 [2] 3f b7 [2] 39 82 [2] 17 82 [2] 28 9e }

  condition:
    any of them
}