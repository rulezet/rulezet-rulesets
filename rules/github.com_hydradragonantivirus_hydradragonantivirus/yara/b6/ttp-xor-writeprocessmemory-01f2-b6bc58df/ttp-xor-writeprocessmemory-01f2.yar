rule TTP_XOR_WriteProcessMemory_01f2 {
  strings:
    $key_01f2 = { 56 80 [2] 64 a2 [2] 62 97 [2] 4c 97 [2] 73 8b }

  condition:
    any of them
}