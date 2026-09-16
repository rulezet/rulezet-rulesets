rule TTP_XOR_WriteProcessMemory_2731 {
  strings:
    $key_2731 = { 70 43 [2] 42 61 [2] 44 54 [2] 6a 54 [2] 55 48 }

  condition:
    any of them
}