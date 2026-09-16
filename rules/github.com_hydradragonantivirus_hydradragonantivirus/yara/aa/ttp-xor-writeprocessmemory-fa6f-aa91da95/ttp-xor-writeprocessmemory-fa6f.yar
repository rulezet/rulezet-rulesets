rule TTP_XOR_WriteProcessMemory_fa6f {
  strings:
    $key_fa6f = { ad 1d [2] 9f 3f [2] 99 0a [2] b7 0a [2] 88 16 }

  condition:
    any of them
}