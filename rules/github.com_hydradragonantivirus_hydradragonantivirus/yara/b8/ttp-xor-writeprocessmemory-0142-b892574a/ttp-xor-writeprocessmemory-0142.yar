rule TTP_XOR_WriteProcessMemory_0142 {
  strings:
    $key_0142 = { 56 30 [2] 64 12 [2] 62 27 [2] 4c 27 [2] 73 3b }

  condition:
    any of them
}