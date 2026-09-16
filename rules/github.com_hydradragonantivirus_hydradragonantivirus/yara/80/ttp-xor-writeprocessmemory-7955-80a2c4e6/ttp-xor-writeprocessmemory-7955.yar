rule TTP_XOR_WriteProcessMemory_7955 {
  strings:
    $key_7955 = { 2e 27 [2] 1c 05 [2] 1a 30 [2] 34 30 [2] 0b 2c }

  condition:
    any of them
}