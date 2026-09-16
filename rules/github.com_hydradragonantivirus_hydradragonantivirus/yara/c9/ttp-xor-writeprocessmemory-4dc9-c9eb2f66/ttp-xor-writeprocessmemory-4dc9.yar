rule TTP_XOR_WriteProcessMemory_4dc9 {
  strings:
    $key_4dc9 = { 1a bb [2] 28 99 [2] 2e ac [2] 00 ac [2] 3f b0 }

  condition:
    any of them
}