rule TTP_XOR_WriteProcessMemory_f58c {
  strings:
    $key_f58c = { a2 fe [2] 90 dc [2] 96 e9 [2] b8 e9 [2] 87 f5 }

  condition:
    any of them
}