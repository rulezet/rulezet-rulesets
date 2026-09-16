rule TTP_XOR_WriteProcessMemory_3310 {
  strings:
    $key_3310 = { 64 62 [2] 56 40 [2] 50 75 [2] 7e 75 [2] 41 69 }

  condition:
    any of them
}