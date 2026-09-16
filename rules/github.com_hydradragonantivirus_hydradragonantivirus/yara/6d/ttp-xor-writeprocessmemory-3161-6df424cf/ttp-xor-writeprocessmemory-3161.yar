rule TTP_XOR_WriteProcessMemory_3161 {
  strings:
    $key_3161 = { 66 13 [2] 54 31 [2] 52 04 [2] 7c 04 [2] 43 18 }

  condition:
    any of them
}