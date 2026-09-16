rule TTP_XOR_WriteProcessMemory_c3ae {
  strings:
    $key_c3ae = { 94 dc [2] a6 fe [2] a0 cb [2] 8e cb [2] b1 d7 }

  condition:
    any of them
}