rule TTP_XOR_WriteProcessMemory_1182 {
  strings:
    $key_1182 = { 46 f0 [2] 74 d2 [2] 72 e7 [2] 5c e7 [2] 63 fb }

  condition:
    any of them
}