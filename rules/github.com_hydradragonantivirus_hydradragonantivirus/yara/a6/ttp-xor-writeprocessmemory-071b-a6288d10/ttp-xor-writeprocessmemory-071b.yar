rule TTP_XOR_WriteProcessMemory_071b {
  strings:
    $key_071b = { 50 69 [2] 62 4b [2] 64 7e [2] 4a 7e [2] 75 62 }

  condition:
    any of them
}