rule TTP_XOR_WriteProcessMemory_48c9 {
  strings:
    $key_48c9 = { 1f bb [2] 2d 99 [2] 2b ac [2] 05 ac [2] 3a b0 }

  condition:
    any of them
}