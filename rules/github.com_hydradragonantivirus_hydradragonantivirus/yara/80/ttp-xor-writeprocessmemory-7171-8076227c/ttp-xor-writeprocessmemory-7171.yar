rule TTP_XOR_WriteProcessMemory_7171 {
  strings:
    $key_7171 = { 26 03 [2] 14 21 [2] 12 14 [2] 3c 14 [2] 03 08 }

  condition:
    any of them
}