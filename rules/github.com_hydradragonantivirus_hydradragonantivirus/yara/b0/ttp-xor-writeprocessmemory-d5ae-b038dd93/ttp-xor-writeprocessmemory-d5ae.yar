rule TTP_XOR_WriteProcessMemory_d5ae {
  strings:
    $key_d5ae = { 82 dc [2] b0 fe [2] b6 cb [2] 98 cb [2] a7 d7 }

  condition:
    any of them
}