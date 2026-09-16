rule TTP_XOR_WriteProcessMemory_e220 {
  strings:
    $key_e220 = { b5 52 [2] 87 70 [2] 81 45 [2] af 45 [2] 90 59 }

  condition:
    any of them
}