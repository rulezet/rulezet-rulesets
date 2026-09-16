rule TTP_XOR_WriteProcessMemory_e207 {
  strings:
    $key_e207 = { b5 75 [2] 87 57 [2] 81 62 [2] af 62 [2] 90 7e }

  condition:
    any of them
}