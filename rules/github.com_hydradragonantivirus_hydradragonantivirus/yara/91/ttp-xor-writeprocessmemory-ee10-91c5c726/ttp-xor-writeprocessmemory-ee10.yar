rule TTP_XOR_WriteProcessMemory_ee10 {
  strings:
    $key_ee10 = { b9 62 [2] 8b 40 [2] 8d 75 [2] a3 75 [2] 9c 69 }

  condition:
    any of them
}