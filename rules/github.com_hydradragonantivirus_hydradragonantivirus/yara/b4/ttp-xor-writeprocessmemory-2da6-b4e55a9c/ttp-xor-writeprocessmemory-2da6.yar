rule TTP_XOR_WriteProcessMemory_2da6 {
  strings:
    $key_2da6 = { 7a d4 [2] 48 f6 [2] 4e c3 [2] 60 c3 [2] 5f df }

  condition:
    any of them
}