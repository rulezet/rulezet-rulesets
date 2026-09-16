rule TTP_XOR_WriteProcessMemory_2b10 {
  strings:
    $key_2b10 = { 7c 62 [2] 4e 40 [2] 48 75 [2] 66 75 [2] 59 69 }

  condition:
    any of them
}