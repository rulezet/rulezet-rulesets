rule TTP_XOR_WriteProcessMemory_eff5 {
  strings:
    $key_eff5 = { b8 87 [2] 8a a5 [2] 8c 90 [2] a2 90 [2] 9d 8c }

  condition:
    any of them
}