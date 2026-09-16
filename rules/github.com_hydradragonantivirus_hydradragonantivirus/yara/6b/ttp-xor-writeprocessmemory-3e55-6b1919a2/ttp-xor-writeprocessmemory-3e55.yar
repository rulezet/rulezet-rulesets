rule TTP_XOR_WriteProcessMemory_3e55 {
  strings:
    $key_3e55 = { 69 27 [2] 5b 05 [2] 5d 30 [2] 73 30 [2] 4c 2c }

  condition:
    any of them
}