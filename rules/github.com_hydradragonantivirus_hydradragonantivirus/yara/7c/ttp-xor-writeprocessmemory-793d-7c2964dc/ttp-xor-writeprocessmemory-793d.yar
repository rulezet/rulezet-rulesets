rule TTP_XOR_WriteProcessMemory_793d {
  strings:
    $key_793d = { 2e 4f [2] 1c 6d [2] 1a 58 [2] 34 58 [2] 0b 44 }

  condition:
    any of them
}