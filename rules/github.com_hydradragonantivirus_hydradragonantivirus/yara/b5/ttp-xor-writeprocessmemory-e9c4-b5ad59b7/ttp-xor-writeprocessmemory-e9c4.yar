rule TTP_XOR_WriteProcessMemory_e9c4 {
  strings:
    $key_e9c4 = { be b6 [2] 8c 94 [2] 8a a1 [2] a4 a1 [2] 9b bd }

  condition:
    any of them
}