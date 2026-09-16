rule TTP_XOR_WriteProcessMemory_e273 {
  strings:
    $key_e273 = { b5 01 [2] 87 23 [2] 81 16 [2] af 16 [2] 90 0a }

  condition:
    any of them
}