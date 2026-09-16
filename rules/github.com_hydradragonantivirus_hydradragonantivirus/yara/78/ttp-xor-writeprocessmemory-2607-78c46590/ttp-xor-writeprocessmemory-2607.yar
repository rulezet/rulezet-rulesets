rule TTP_XOR_WriteProcessMemory_2607 {
  strings:
    $key_2607 = { 71 75 [2] 43 57 [2] 45 62 [2] 6b 62 [2] 54 7e }

  condition:
    any of them
}