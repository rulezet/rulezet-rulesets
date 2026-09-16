rule TTP_XOR_WriteProcessMemory_0951 {
  strings:
    $key_0951 = { 5e 23 [2] 6c 01 [2] 6a 34 [2] 44 34 [2] 7b 28 }

  condition:
    any of them
}