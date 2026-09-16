rule TTP_XOR_WriteProcessMemory_3623 {
  strings:
    $key_3623 = { 61 51 [2] 53 73 [2] 55 46 [2] 7b 46 [2] 44 5a }

  condition:
    any of them
}