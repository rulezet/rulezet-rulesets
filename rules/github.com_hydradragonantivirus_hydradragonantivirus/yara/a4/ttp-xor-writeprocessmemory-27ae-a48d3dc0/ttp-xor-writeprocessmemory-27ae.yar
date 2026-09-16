rule TTP_XOR_WriteProcessMemory_27ae {
  strings:
    $key_27ae = { 70 dc [2] 42 fe [2] 44 cb [2] 6a cb [2] 55 d7 }

  condition:
    any of them
}