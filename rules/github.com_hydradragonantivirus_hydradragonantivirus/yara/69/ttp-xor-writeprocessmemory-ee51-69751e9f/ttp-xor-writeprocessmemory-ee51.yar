rule TTP_XOR_WriteProcessMemory_ee51 {
  strings:
    $key_ee51 = { b9 23 [2] 8b 01 [2] 8d 34 [2] a3 34 [2] 9c 28 }

  condition:
    any of them
}