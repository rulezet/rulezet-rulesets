rule TTP_XOR_WriteProcessMemory_4951 {
  strings:
    $key_4951 = { 1e 23 [2] 2c 01 [2] 2a 34 [2] 04 34 [2] 3b 28 }

  condition:
    any of them
}