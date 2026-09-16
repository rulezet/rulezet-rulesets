rule TTP_XOR_WriteProcessMemory_e735 {
  strings:
    $key_e735 = { b0 47 [2] 82 65 [2] 84 50 [2] aa 50 [2] 95 4c }

  condition:
    any of them
}