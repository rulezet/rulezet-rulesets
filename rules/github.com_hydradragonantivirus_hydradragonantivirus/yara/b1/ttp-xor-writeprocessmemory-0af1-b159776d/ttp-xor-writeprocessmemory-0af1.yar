rule TTP_XOR_WriteProcessMemory_0af1 {
  strings:
    $key_0af1 = { 5d 83 [2] 6f a1 [2] 69 94 [2] 47 94 [2] 78 88 }

  condition:
    any of them
}