rule TTP_XOR_WriteProcessMemory_e75d {
  strings:
    $key_e75d = { b0 2f [2] 82 0d [2] 84 38 [2] aa 38 [2] 95 24 }

  condition:
    any of them
}