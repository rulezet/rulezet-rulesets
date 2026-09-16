rule TTP_XOR_WriteProcessMemory_6dc9 {
  strings:
    $key_6dc9 = { 3a bb [2] 08 99 [2] 0e ac [2] 20 ac [2] 1f b0 }

  condition:
    any of them
}