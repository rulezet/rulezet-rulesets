rule TTP_XOR_WriteProcessMemory_0163 {
  strings:
    $key_0163 = { 56 11 [2] 64 33 [2] 62 06 [2] 4c 06 [2] 73 1a }

  condition:
    any of them
}