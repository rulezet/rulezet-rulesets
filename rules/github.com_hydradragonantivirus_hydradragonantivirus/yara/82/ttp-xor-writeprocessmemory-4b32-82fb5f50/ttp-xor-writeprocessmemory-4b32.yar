rule TTP_XOR_WriteProcessMemory_4b32 {
  strings:
    $key_4b32 = { 1c 40 [2] 2e 62 [2] 28 57 [2] 06 57 [2] 39 4b }

  condition:
    any of them
}