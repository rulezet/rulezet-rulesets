rule TTP_XOR_WriteProcessMemory_1393 {
  strings:
    $key_1393 = { 44 e1 [2] 76 c3 [2] 70 f6 [2] 5e f6 [2] 61 ea }

  condition:
    any of them
}