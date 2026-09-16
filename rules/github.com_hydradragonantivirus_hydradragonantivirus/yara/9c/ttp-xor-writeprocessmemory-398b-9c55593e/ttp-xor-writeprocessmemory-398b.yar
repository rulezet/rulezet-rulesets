rule TTP_XOR_WriteProcessMemory_398b {
  strings:
    $key_398b = { 6e f9 [2] 5c db [2] 5a ee [2] 74 ee [2] 4b f2 }

  condition:
    any of them
}