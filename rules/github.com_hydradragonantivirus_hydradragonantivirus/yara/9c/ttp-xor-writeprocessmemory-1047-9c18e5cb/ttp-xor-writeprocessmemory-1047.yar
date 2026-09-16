rule TTP_XOR_WriteProcessMemory_1047 {
  strings:
    $key_1047 = { 47 35 [2] 75 17 [2] 73 22 [2] 5d 22 [2] 62 3e }

  condition:
    any of them
}