rule TTP_XOR_WriteProcessMemory_31f7 {
  strings:
    $key_31f7 = { 66 85 [2] 54 a7 [2] 52 92 [2] 7c 92 [2] 43 8e }

  condition:
    any of them
}