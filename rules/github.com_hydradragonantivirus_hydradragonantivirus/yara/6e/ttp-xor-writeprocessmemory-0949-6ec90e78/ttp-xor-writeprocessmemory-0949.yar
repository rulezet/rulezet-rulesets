rule TTP_XOR_WriteProcessMemory_0949 {
  strings:
    $key_0949 = { 5e 3b [2] 6c 19 [2] 6a 2c [2] 44 2c [2] 7b 30 }

  condition:
    any of them
}