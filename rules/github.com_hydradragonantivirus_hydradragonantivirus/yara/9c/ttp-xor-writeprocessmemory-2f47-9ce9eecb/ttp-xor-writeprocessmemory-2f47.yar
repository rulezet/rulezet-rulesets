rule TTP_XOR_WriteProcessMemory_2f47 {
  strings:
    $key_2f47 = { 78 35 [2] 4a 17 [2] 4c 22 [2] 62 22 [2] 5d 3e }

  condition:
    any of them
}