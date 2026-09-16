rule TTP_XOR_WriteProcessMemory_e66a {
  strings:
    $key_e66a = { b1 18 [2] 83 3a [2] 85 0f [2] ab 0f [2] 94 13 }

  condition:
    any of them
}