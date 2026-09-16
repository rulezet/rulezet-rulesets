rule TTP_XOR_WriteProcessMemory_fa5a {
  strings:
    $key_fa5a = { ad 28 [2] 9f 0a [2] 99 3f [2] b7 3f [2] 88 23 }

  condition:
    any of them
}