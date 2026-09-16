rule TTP_XOR_WriteProcessMemory_3c37 {
  strings:
    $key_3c37 = { 6b 45 [2] 59 67 [2] 5f 52 [2] 71 52 [2] 4e 4e }

  condition:
    any of them
}