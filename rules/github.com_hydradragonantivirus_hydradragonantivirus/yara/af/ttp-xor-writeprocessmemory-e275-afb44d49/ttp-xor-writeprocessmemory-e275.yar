rule TTP_XOR_WriteProcessMemory_e275 {
  strings:
    $key_e275 = { b5 07 [2] 87 25 [2] 81 10 [2] af 10 [2] 90 0c }

  condition:
    any of them
}