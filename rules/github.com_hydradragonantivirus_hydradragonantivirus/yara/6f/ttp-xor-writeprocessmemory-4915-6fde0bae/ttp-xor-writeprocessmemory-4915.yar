rule TTP_XOR_WriteProcessMemory_4915 {
  strings:
    $key_4915 = { 1e 67 [2] 2c 45 [2] 2a 70 [2] 04 70 [2] 3b 6c }

  condition:
    any of them
}