rule TTP_XOR_WriteProcessMemory_e233 {
  strings:
    $key_e233 = { b5 41 [2] 87 63 [2] 81 56 [2] af 56 [2] 90 4a }

  condition:
    any of them
}