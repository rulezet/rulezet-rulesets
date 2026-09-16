rule TTP_XOR_WriteProcessMemory_4110 {
  strings:
    $key_4110 = { 16 62 [2] 24 40 [2] 22 75 [2] 0c 75 [2] 33 69 }

  condition:
    any of them
}