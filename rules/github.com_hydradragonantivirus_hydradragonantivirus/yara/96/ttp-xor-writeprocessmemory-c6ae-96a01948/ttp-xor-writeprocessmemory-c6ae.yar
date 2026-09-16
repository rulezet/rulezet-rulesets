rule TTP_XOR_WriteProcessMemory_c6ae {
  strings:
    $key_c6ae = { 91 dc [2] a3 fe [2] a5 cb [2] 8b cb [2] b4 d7 }

  condition:
    any of them
}