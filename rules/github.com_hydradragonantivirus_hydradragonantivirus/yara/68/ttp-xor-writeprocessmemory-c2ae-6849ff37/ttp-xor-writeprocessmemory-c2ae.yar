rule TTP_XOR_WriteProcessMemory_c2ae {
  strings:
    $key_c2ae = { 95 dc [2] a7 fe [2] a1 cb [2] 8f cb [2] b0 d7 }

  condition:
    any of them
}