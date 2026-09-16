rule TTP_XOR_WriteProcessMemory_ee22 {
  strings:
    $key_ee22 = { b9 50 [2] 8b 72 [2] 8d 47 [2] a3 47 [2] 9c 5b }

  condition:
    any of them
}