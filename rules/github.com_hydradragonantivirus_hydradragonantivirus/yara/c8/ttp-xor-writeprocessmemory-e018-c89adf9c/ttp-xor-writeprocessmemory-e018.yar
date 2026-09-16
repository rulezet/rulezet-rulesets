rule TTP_XOR_WriteProcessMemory_e018 {
  strings:
    $key_e018 = { b7 6a [2] 85 48 [2] 83 7d [2] ad 7d [2] 92 61 }

  condition:
    any of them
}