rule TTP_XOR_WriteProcessMemory_6455 {
  strings:
    $key_6455 = { 33 27 [2] 01 05 [2] 07 30 [2] 29 30 [2] 16 2c }

  condition:
    any of them
}