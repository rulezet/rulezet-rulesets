rule TTP_XOR_WriteProcessMemory_1017 {
  strings:
    $key_1017 = { 47 65 [2] 75 47 [2] 73 72 [2] 5d 72 [2] 62 6e }

  condition:
    any of them
}