rule TTP_XOR_WriteProcessMemory_fa1f {
  strings:
    $key_fa1f = { ad 6d [2] 9f 4f [2] 99 7a [2] b7 7a [2] 88 66 }

  condition:
    any of them
}