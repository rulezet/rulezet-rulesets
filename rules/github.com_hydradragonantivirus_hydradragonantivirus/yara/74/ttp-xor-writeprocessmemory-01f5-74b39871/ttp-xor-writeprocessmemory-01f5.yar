rule TTP_XOR_WriteProcessMemory_01f5 {
  strings:
    $key_01f5 = { 56 87 [2] 64 a5 [2] 62 90 [2] 4c 90 [2] 73 8c }

  condition:
    any of them
}