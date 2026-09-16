rule TTP_XOR_WriteProcessMemory_d58c {
  strings:
    $key_d58c = { 82 fe [2] b0 dc [2] b6 e9 [2] 98 e9 [2] a7 f5 }

  condition:
    any of them
}