rule TTP_XOR_WriteProcessMemory_e02a {
  strings:
    $key_e02a = { b7 58 [2] 85 7a [2] 83 4f [2] ad 4f [2] 92 53 }

  condition:
    any of them
}