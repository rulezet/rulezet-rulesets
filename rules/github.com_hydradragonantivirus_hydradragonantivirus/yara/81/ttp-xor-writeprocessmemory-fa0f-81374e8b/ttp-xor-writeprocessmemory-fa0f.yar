rule TTP_XOR_WriteProcessMemory_fa0f {
  strings:
    $key_fa0f = { ad 7d [2] 9f 5f [2] 99 6a [2] b7 6a [2] 88 76 }

  condition:
    any of them
}