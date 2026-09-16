rule TTP_XOR_WriteProcessMemory_0249 {
  strings:
    $key_0249 = { 55 3b [2] 67 19 [2] 61 2c [2] 4f 2c [2] 70 30 }

  condition:
    any of them
}