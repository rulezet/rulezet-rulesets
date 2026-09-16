rule TTP_XOR_WriteProcessMemory_e06a {
  strings:
    $key_e06a = { b7 18 [2] 85 3a [2] 83 0f [2] ad 0f [2] 92 13 }

  condition:
    any of them
}