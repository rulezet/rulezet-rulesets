rule TTP_XOR_WriteProcessMemory_e01a {
  strings:
    $key_e01a = { b7 68 [2] 85 4a [2] 83 7f [2] ad 7f [2] 92 63 }

  condition:
    any of them
}