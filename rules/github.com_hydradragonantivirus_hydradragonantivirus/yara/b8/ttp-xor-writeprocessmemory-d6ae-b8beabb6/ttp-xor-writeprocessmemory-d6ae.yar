rule TTP_XOR_WriteProcessMemory_d6ae {
  strings:
    $key_d6ae = { 81 dc [2] b3 fe [2] b5 cb [2] 9b cb [2] a4 d7 }

  condition:
    any of them
}