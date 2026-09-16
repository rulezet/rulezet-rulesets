rule TTP_XOR_WriteProcessMemory_fa78 {
  strings:
    $key_fa78 = { ad 0a [2] 9f 28 [2] 99 1d [2] b7 1d [2] 88 01 }

  condition:
    any of them
}