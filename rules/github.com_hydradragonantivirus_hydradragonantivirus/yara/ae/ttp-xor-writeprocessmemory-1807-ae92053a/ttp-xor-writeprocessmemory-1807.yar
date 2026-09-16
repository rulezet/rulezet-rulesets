rule TTP_XOR_WriteProcessMemory_1807 {
  strings:
    $key_1807 = { 4f 75 [2] 7d 57 [2] 7b 62 [2] 55 62 [2] 6a 7e }

  condition:
    any of them
}