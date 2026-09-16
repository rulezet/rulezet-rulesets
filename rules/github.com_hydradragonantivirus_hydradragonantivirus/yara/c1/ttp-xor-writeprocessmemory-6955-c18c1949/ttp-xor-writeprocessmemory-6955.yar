rule TTP_XOR_WriteProcessMemory_6955 {
  strings:
    $key_6955 = { 3e 27 [2] 0c 05 [2] 0a 30 [2] 24 30 [2] 1b 2c }

  condition:
    any of them
}