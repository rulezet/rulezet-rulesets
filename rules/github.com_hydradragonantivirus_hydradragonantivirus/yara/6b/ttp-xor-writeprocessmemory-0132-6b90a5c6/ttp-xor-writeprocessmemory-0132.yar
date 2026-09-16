rule TTP_XOR_WriteProcessMemory_0132 {
  strings:
    $key_0132 = { 56 40 [2] 64 62 [2] 62 57 [2] 4c 57 [2] 73 4b }

  condition:
    any of them
}