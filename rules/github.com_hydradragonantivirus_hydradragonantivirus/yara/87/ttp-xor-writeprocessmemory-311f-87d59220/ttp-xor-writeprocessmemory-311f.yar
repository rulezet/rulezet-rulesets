rule TTP_XOR_WriteProcessMemory_311f {
  strings:
    $key_311f = { 66 6d [2] 54 4f [2] 52 7a [2] 7c 7a [2] 43 66 }

  condition:
    any of them
}