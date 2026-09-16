rule TTP_XOR_WriteProcessMemory_dee6 {
  strings:
    $key_dee6 = { 89 94 [2] bb b6 [2] bd 83 [2] 93 83 [2] ac 9f }

  condition:
    any of them
}