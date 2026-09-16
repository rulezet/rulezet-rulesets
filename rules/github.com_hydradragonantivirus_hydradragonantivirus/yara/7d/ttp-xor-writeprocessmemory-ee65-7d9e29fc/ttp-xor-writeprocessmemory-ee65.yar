rule TTP_XOR_WriteProcessMemory_ee65 {
  strings:
    $key_ee65 = { b9 17 [2] 8b 35 [2] 8d 00 [2] a3 00 [2] 9c 1c }

  condition:
    any of them
}