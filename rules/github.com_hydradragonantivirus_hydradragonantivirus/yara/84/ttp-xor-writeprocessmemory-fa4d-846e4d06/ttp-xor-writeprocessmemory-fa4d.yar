rule TTP_XOR_WriteProcessMemory_fa4d {
  strings:
    $key_fa4d = { ad 3f [2] 9f 1d [2] 99 28 [2] b7 28 [2] 88 34 }

  condition:
    any of them
}