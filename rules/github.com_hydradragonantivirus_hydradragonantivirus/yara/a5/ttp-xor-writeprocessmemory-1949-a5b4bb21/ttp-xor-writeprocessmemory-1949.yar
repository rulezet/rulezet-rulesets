rule TTP_XOR_WriteProcessMemory_1949 {
  strings:
    $key_1949 = { 4e 3b [2] 7c 19 [2] 7a 2c [2] 54 2c [2] 6b 30 }

  condition:
    any of them
}