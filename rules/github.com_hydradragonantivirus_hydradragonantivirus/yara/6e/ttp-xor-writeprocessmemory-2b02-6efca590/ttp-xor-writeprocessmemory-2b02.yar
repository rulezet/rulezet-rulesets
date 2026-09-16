rule TTP_XOR_WriteProcessMemory_2b02 {
  strings:
    $key_2b02 = { 7c 70 [2] 4e 52 [2] 48 67 [2] 66 67 [2] 59 7b }

  condition:
    any of them
}