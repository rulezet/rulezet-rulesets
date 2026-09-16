rule TTP_XOR_WriteProcessMemory_2b07 {
  strings:
    $key_2b07 = { 7c 75 [2] 4e 57 [2] 48 62 [2] 66 62 [2] 59 7e }

  condition:
    any of them
}