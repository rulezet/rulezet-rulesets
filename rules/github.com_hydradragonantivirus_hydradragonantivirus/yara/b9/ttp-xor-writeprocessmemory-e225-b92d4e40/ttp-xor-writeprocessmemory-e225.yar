rule TTP_XOR_WriteProcessMemory_e225 {
  strings:
    $key_e225 = { b5 57 [2] 87 75 [2] 81 40 [2] af 40 [2] 90 5c }

  condition:
    any of them
}