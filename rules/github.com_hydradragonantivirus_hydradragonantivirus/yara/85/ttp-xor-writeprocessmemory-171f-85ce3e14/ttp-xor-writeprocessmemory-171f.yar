rule TTP_XOR_WriteProcessMemory_171f {
  strings:
    $key_171f = { 40 6d [2] 72 4f [2] 74 7a [2] 5a 7a [2] 65 66 }

  condition:
    any of them
}