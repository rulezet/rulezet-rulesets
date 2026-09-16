rule TTP_XOR_WriteProcessMemory_79c9 {
  strings:
    $key_79c9 = { 2e bb [2] 1c 99 [2] 1a ac [2] 34 ac [2] 0b b0 }

  condition:
    any of them
}