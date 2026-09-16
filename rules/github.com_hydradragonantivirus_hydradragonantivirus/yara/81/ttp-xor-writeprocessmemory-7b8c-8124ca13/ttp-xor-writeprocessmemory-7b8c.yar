rule TTP_XOR_WriteProcessMemory_7b8c {
  strings:
    $key_7b8c = { 2c fe [2] 1e dc [2] 18 e9 [2] 36 e9 [2] 09 f5 }

  condition:
    any of them
}