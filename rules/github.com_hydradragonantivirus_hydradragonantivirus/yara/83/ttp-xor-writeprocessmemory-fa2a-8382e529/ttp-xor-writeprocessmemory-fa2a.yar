rule TTP_XOR_WriteProcessMemory_fa2a {
  strings:
    $key_fa2a = { ad 58 [2] 9f 7a [2] 99 4f [2] b7 4f [2] 88 53 }

  condition:
    any of them
}