rule TTP_XOR_WriteProcessMemory_398c {
  strings:
    $key_398c = { 6e fe [2] 5c dc [2] 5a e9 [2] 74 e9 [2] 4b f5 }

  condition:
    any of them
}