rule TTP_XOR_WriteProcessMemory_e775 {
  strings:
    $key_e775 = { b0 07 [2] 82 25 [2] 84 10 [2] aa 10 [2] 95 0c }

  condition:
    any of them
}