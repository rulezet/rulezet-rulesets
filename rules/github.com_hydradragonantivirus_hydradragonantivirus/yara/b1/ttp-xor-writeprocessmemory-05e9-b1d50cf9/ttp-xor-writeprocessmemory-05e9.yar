rule TTP_XOR_WriteProcessMemory_05e9 {
  strings:
    $key_05e9 = { 52 9b [2] 60 b9 [2] 66 8c [2] 48 8c [2] 77 90 }

  condition:
    any of them
}