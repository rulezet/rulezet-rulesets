rule TTP_XOR_WriteProcessMemory_5161 {
  strings:
    $key_5161 = { 06 13 [2] 34 31 [2] 32 04 [2] 1c 04 [2] 23 18 }

  condition:
    any of them
}