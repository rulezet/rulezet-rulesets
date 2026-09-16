rule TTP_XOR_WriteProcessMemory_698c {
  strings:
    $key_698c = { 3e fe [2] 0c dc [2] 0a e9 [2] 24 e9 [2] 1b f5 }

  condition:
    any of them
}