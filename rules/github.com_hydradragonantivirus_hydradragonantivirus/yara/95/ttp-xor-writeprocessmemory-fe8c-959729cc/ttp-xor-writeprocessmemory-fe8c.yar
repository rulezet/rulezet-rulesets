rule TTP_XOR_WriteProcessMemory_fe8c {
  strings:
    $key_fe8c = { a9 fe [2] 9b dc [2] 9d e9 [2] b3 e9 [2] 8c f5 }

  condition:
    any of them
}