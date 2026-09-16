rule TTP_XOR_WriteProcessMemory_e277 {
  strings:
    $key_e277 = { b5 05 [2] 87 27 [2] 81 12 [2] af 12 [2] 90 0e }

  condition:
    any of them
}