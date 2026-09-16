rule TTP_XOR_WriteProcessMemory_e65a {
  strings:
    $key_e65a = { b1 28 [2] 83 0a [2] 85 3f [2] ab 3f [2] 94 23 }

  condition:
    any of them
}