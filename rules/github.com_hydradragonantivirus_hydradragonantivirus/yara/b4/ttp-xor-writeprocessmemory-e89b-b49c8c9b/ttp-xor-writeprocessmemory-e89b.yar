rule TTP_XOR_WriteProcessMemory_e89b {
  strings:
    $key_e89b = { bf e9 [2] 8d cb [2] 8b fe [2] a5 fe [2] 9a e2 }

  condition:
    any of them
}