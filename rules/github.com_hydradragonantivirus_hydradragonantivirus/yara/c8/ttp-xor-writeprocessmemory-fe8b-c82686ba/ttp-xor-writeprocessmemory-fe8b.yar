rule TTP_XOR_WriteProcessMemory_fe8b {
  strings:
    $key_fe8b = { a9 f9 [2] 9b db [2] 9d ee [2] b3 ee [2] 8c f2 }

  condition:
    any of them
}