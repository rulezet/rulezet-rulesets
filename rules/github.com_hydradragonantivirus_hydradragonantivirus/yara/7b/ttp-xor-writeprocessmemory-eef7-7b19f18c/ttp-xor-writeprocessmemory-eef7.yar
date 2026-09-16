rule TTP_XOR_WriteProcessMemory_eef7 {
  strings:
    $key_eef7 = { b9 85 [2] 8b a7 [2] 8d 92 [2] a3 92 [2] 9c 8e }

  condition:
    any of them
}