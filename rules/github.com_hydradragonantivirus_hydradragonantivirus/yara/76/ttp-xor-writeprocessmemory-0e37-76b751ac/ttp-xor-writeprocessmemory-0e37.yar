rule TTP_XOR_WriteProcessMemory_0e37 {
  strings:
    $key_0e37 = { 59 45 [2] 6b 67 [2] 6d 52 [2] 43 52 [2] 7c 4e }

  condition:
    any of them
}