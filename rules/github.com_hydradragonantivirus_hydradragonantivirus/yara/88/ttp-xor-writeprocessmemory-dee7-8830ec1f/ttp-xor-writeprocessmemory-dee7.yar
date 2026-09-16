rule TTP_XOR_WriteProcessMemory_dee7 {
  strings:
    $key_dee7 = { 89 95 [2] bb b7 [2] bd 82 [2] 93 82 [2] ac 9e }

  condition:
    any of them
}