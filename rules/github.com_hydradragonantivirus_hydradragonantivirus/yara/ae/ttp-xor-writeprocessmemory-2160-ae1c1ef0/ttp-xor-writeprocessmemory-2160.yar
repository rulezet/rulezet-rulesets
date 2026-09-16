rule TTP_XOR_WriteProcessMemory_2160 {
  strings:
    $key_2160 = { 76 12 [2] 44 30 [2] 42 05 [2] 6c 05 [2] 53 19 }

  condition:
    any of them
}