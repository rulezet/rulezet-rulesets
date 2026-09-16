rule TTP_XOR_WriteProcessMemory_e222 {
  strings:
    $key_e222 = { b5 50 [2] 87 72 [2] 81 47 [2] af 47 [2] 90 5b }

  condition:
    any of them
}