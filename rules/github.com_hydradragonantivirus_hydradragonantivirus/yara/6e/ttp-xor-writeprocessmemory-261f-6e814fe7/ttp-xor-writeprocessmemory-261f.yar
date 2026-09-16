rule TTP_XOR_WriteProcessMemory_261f {
  strings:
    $key_261f = { 71 6d [2] 43 4f [2] 45 7a [2] 6b 7a [2] 54 66 }

  condition:
    any of them
}