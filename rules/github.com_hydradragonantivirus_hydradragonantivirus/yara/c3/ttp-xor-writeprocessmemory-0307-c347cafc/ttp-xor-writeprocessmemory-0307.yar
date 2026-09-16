rule TTP_XOR_WriteProcessMemory_0307 {
  strings:
    $key_0307 = { 54 75 [2] 66 57 [2] 60 62 [2] 4e 62 [2] 71 7e }

  condition:
    any of them
}