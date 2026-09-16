rule TTP_XOR_WriteProcessMemory_e261 {
  strings:
    $key_e261 = { b5 13 [2] 87 31 [2] 81 04 [2] af 04 [2] 90 18 }

  condition:
    any of them
}