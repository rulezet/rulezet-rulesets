rule TTP_XOR_WriteProcessMemory_e202 {
  strings:
    $key_e202 = { b5 70 [2] 87 52 [2] 81 67 [2] af 67 [2] 90 7b }

  condition:
    any of them
}