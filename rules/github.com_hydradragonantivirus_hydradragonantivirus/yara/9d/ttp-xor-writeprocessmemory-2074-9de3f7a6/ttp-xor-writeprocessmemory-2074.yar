rule TTP_XOR_WriteProcessMemory_2074 {
  strings:
    $key_2074 = { 77 06 [2] 45 24 [2] 43 11 [2] 6d 11 [2] 52 0d }

  condition:
    any of them
}