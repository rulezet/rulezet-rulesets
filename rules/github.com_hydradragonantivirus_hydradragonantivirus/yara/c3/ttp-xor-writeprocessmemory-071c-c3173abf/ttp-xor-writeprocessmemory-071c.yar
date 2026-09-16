rule TTP_XOR_WriteProcessMemory_071c {
  strings:
    $key_071c = { 50 6e [2] 62 4c [2] 64 79 [2] 4a 79 [2] 75 65 }

  condition:
    any of them
}