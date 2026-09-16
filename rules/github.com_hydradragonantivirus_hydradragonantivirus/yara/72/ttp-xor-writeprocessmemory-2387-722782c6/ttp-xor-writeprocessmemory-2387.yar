rule TTP_XOR_WriteProcessMemory_2387 {
  strings:
    $key_2387 = { 74 f5 [2] 46 d7 [2] 40 e2 [2] 6e e2 [2] 51 fe }

  condition:
    any of them
}