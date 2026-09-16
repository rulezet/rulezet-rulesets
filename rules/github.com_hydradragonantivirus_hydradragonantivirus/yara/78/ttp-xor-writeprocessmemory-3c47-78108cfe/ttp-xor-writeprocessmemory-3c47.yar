rule TTP_XOR_WriteProcessMemory_3c47 {
  strings:
    $key_3c47 = { 6b 35 [2] 59 17 [2] 5f 22 [2] 71 22 [2] 4e 3e }

  condition:
    any of them
}