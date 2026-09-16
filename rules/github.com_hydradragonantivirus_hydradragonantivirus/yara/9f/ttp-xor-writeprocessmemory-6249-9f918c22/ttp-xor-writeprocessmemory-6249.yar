rule TTP_XOR_WriteProcessMemory_6249 {
  strings:
    $key_6249 = { 35 3b [2] 07 19 [2] 01 2c [2] 2f 2c [2] 10 30 }

  condition:
    any of them
}