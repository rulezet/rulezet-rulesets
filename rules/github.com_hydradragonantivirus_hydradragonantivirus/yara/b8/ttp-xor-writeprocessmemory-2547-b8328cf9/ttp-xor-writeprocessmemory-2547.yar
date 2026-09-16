rule TTP_XOR_WriteProcessMemory_2547 {
  strings:
    $key_2547 = { 72 35 [2] 40 17 [2] 46 22 [2] 68 22 [2] 57 3e }

  condition:
    any of them
}