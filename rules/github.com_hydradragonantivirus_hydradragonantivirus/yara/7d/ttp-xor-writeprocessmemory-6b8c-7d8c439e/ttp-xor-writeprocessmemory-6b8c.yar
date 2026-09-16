rule TTP_XOR_WriteProcessMemory_6b8c {
  strings:
    $key_6b8c = { 3c fe [2] 0e dc [2] 08 e9 [2] 26 e9 [2] 19 f5 }

  condition:
    any of them
}