rule TTP_XOR_WriteProcessMemory_23f9 {
  strings:
    $key_23f9 = { 74 8b [2] 46 a9 [2] 40 9c [2] 6e 9c [2] 51 80 }

  condition:
    any of them
}