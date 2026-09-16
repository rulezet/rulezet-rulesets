rule TTP_XOR_WriteProcessMemory_561f {
  strings:
    $key_561f = { 01 6d [2] 33 4f [2] 35 7a [2] 1b 7a [2] 24 66 }

  condition:
    any of them
}