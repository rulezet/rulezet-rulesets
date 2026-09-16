rule TTP_XOR_WriteProcessMemory_2014 {
  strings:
    $key_2014 = { 77 66 [2] 45 44 [2] 43 71 [2] 6d 71 [2] 52 6d }

  condition:
    any of them
}