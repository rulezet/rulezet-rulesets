rule TTP_XOR_WriteProcessMemory_0524 {
  strings:
    $key_0524 = { 52 56 [2] 60 74 [2] 66 41 [2] 48 41 [2] 77 5d }

  condition:
    any of them
}