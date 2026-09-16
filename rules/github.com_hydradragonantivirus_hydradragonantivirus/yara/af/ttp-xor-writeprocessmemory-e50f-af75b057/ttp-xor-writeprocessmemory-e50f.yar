rule TTP_XOR_WriteProcessMemory_e50f {
  strings:
    $key_e50f = { b2 7d [2] 80 5f [2] 86 6a [2] a8 6a [2] 97 76 }

  condition:
    any of them
}