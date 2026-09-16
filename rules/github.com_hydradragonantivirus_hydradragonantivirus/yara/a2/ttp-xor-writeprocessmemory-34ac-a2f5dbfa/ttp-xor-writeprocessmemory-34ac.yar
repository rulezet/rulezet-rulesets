rule TTP_XOR_WriteProcessMemory_34ac {
  strings:
    $key_34ac = { 63 de [2] 51 fc [2] 57 c9 [2] 79 c9 [2] 46 d5 }

  condition:
    any of them
}