rule TTP_XOR_WriteProcessMemory_fa7a {
  strings:
    $key_fa7a = { ad 08 [2] 9f 2a [2] 99 1f [2] b7 1f [2] 88 03 }

  condition:
    any of them
}