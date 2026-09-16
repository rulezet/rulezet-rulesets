rule TTP_XOR_WriteProcessMemory_5c96 {
  strings:
    $key_5c96 = { 0b e4 [2] 39 c6 [2] 3f f3 [2] 11 f3 [2] 2e ef }

  condition:
    any of them
}