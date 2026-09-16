rule TTP_XOR_WriteProcessMemory_01f7 {
  strings:
    $key_01f7 = { 56 85 [2] 64 a7 [2] 62 92 [2] 4c 92 [2] 73 8e }

  condition:
    any of them
}