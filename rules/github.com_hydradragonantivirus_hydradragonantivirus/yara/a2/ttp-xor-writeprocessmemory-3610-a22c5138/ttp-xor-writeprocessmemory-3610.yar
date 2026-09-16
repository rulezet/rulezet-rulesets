rule TTP_XOR_WriteProcessMemory_3610 {
  strings:
    $key_3610 = { 61 62 [2] 53 40 [2] 55 75 [2] 7b 75 [2] 44 69 }

  condition:
    any of them
}