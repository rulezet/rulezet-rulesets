rule TTP_XOR_WriteProcessMemory_0b8c {
  strings:
    $key_0b8c = { 5c fe [2] 6e dc [2] 68 e9 [2] 46 e9 [2] 79 f5 }

  condition:
    any of them
}