rule TTP_XOR_WriteProcessMemory_e50a {
  strings:
    $key_e50a = { b2 78 [2] 80 5a [2] 86 6f [2] a8 6f [2] 97 73 }

  condition:
    any of them
}