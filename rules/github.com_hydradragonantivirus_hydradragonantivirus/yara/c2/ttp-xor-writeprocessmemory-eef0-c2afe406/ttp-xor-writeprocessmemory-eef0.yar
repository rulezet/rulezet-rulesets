rule TTP_XOR_WriteProcessMemory_eef0 {
  strings:
    $key_eef0 = { b9 82 [2] 8b a0 [2] 8d 95 [2] a3 95 [2] 9c 89 }

  condition:
    any of them
}