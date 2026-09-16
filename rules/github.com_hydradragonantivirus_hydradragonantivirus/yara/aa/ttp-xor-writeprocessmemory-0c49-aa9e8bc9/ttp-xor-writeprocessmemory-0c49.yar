rule TTP_XOR_WriteProcessMemory_0c49 {
  strings:
    $key_0c49 = { 5b 3b [2] 69 19 [2] 6f 2c [2] 41 2c [2] 7e 30 }

  condition:
    any of them
}