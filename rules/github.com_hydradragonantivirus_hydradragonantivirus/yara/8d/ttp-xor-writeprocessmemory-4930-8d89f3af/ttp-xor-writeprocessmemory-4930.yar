rule TTP_XOR_WriteProcessMemory_4930 {
  strings:
    $key_4930 = { 1e 42 [2] 2c 60 [2] 2a 55 [2] 04 55 [2] 3b 49 }

  condition:
    any of them
}