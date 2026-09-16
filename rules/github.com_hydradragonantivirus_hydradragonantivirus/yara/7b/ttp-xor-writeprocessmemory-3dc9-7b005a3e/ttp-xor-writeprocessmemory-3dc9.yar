rule TTP_XOR_WriteProcessMemory_3dc9 {
  strings:
    $key_3dc9 = { 6a bb [2] 58 99 [2] 5e ac [2] 70 ac [2] 4f b0 }

  condition:
    any of them
}