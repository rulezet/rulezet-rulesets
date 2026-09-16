rule TTP_XOR_WriteProcessMemory_fa3f {
  strings:
    $key_fa3f = { ad 4d [2] 9f 6f [2] 99 5a [2] b7 5a [2] 88 46 }

  condition:
    any of them
}