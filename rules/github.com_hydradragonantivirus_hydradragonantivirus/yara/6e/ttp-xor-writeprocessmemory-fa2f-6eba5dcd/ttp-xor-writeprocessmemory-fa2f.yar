rule TTP_XOR_WriteProcessMemory_fa2f {
  strings:
    $key_fa2f = { ad 5d [2] 9f 7f [2] 99 4a [2] b7 4a [2] 88 56 }

  condition:
    any of them
}