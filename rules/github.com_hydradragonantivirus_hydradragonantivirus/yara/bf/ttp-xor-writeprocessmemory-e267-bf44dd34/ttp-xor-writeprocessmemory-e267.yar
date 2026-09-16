rule TTP_XOR_WriteProcessMemory_e267 {
  strings:
    $key_e267 = { b5 15 [2] 87 37 [2] 81 02 [2] af 02 [2] 90 1e }

  condition:
    any of them
}