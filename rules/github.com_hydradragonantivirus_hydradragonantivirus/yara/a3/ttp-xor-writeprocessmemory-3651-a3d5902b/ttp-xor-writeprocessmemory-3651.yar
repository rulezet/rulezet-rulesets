rule TTP_XOR_WriteProcessMemory_3651 {
  strings:
    $key_3651 = { 61 23 [2] 53 01 [2] 55 34 [2] 7b 34 [2] 44 28 }

  condition:
    any of them
}