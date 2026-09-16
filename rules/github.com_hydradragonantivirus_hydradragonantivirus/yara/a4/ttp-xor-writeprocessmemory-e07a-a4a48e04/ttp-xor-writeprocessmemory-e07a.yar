rule TTP_XOR_WriteProcessMemory_e07a {
  strings:
    $key_e07a = { b7 08 [2] 85 2a [2] 83 1f [2] ad 1f [2] 92 03 }

  condition:
    any of them
}