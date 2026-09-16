rule TTP_XOR_WriteProcessMemory_5d1f {
  strings:
    $key_5d1f = { 0a 6d [2] 38 4f [2] 3e 7a [2] 10 7a [2] 2f 66 }

  condition:
    any of them
}