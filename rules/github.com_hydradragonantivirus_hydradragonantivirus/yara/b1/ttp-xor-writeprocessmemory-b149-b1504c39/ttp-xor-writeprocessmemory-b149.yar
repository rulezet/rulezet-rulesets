rule TTP_XOR_WriteProcessMemory_b149 {
  strings:
    $key_b149 = { e6 3b [2] d4 19 [2] d2 2c [2] fc 2c [2] c3 30 }

  condition:
    any of them
}