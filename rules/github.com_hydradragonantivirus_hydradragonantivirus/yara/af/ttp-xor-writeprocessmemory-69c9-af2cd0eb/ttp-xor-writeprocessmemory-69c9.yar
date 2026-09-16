rule TTP_XOR_WriteProcessMemory_69c9 {
  strings:
    $key_69c9 = { 3e bb [2] 0c 99 [2] 0a ac [2] 24 ac [2] 1b b0 }

  condition:
    any of them
}