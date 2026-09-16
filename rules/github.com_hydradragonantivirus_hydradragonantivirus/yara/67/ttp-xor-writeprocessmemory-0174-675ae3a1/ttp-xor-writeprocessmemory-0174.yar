rule TTP_XOR_WriteProcessMemory_0174 {
  strings:
    $key_0174 = { 56 06 [2] 64 24 [2] 62 11 [2] 4c 11 [2] 73 0d }

  condition:
    any of them
}