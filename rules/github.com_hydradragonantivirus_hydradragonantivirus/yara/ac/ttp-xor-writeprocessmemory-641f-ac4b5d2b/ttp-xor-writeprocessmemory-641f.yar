rule TTP_XOR_WriteProcessMemory_641f {
  strings:
    $key_641f = { 33 6d [2] 01 4f [2] 07 7a [2] 29 7a [2] 16 66 }

  condition:
    any of them
}