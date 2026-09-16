rule TTP_XOR_WriteProcessMemory_0dc9 {
  strings:
    $key_0dc9 = { 5a bb [2] 68 99 [2] 6e ac [2] 40 ac [2] 7f b0 }

  condition:
    any of them
}