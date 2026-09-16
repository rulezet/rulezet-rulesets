rule TTP_XOR_WriteProcessMemory_2034 {
  strings:
    $key_2034 = { 77 46 [2] 45 64 [2] 43 51 [2] 6d 51 [2] 52 4d }

  condition:
    any of them
}