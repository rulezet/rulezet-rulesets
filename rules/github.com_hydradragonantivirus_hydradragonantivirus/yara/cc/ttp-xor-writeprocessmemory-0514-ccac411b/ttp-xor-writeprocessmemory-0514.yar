rule TTP_XOR_WriteProcessMemory_0514 {
  strings:
    $key_0514 = { 52 66 [2] 60 44 [2] 66 71 [2] 48 71 [2] 77 6d }

  condition:
    any of them
}