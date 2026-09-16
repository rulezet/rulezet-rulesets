rule TTP_XOR_WriteProcessMemory_3e07 {
  strings:
    $key_3e07 = { 69 75 [2] 5b 57 [2] 5d 62 [2] 73 62 [2] 4c 7e }

  condition:
    any of them
}