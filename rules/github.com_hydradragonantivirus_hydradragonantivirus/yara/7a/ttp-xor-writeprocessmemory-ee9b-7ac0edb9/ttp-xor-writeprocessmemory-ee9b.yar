rule TTP_XOR_WriteProcessMemory_ee9b {
  strings:
    $key_ee9b = { b9 e9 [2] 8b cb [2] 8d fe [2] a3 fe [2] 9c e2 }

  condition:
    any of them
}