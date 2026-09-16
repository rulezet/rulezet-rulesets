rule TTP_XOR_WriteProcessMemory_52f7 {
  strings:
    $key_52f7 = { 05 85 [2] 37 a7 [2] 31 92 [2] 1f 92 [2] 20 8e }

  condition:
    any of them
}