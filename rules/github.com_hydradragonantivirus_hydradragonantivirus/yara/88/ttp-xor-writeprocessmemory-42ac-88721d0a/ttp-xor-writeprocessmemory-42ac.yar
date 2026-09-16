rule TTP_XOR_WriteProcessMemory_42ac {
  strings:
    $key_42ac = { 15 de [2] 27 fc [2] 21 c9 [2] 0f c9 [2] 30 d5 }

  condition:
    any of them
}