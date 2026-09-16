rule TTP_XOR_WriteProcessMemory_531f {
  strings:
    $key_531f = { 04 6d [2] 36 4f [2] 30 7a [2] 1e 7a [2] 21 66 }

  condition:
    any of them
}