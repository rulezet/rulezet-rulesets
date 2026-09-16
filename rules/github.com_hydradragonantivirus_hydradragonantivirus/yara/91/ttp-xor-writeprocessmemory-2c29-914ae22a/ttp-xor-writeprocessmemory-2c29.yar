rule TTP_XOR_WriteProcessMemory_2c29 {
  strings:
    $key_2c29 = { 7b 5b [2] 49 79 [2] 4f 4c [2] 61 4c [2] 5e 50 }

  condition:
    any of them
}