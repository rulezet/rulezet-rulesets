rule TTP_XOR_WriteProcessMemory_6d10 {
  strings:
    $key_6d10 = { 3a 62 [2] 08 40 [2] 0e 75 [2] 20 75 [2] 1f 69 }

  condition:
    any of them
}