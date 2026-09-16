rule TTP_XOR_WriteProcessMemory_6c96 {
  strings:
    $key_6c96 = { 3b e4 [2] 09 c6 [2] 0f f3 [2] 21 f3 [2] 1e ef }

  condition:
    any of them
}