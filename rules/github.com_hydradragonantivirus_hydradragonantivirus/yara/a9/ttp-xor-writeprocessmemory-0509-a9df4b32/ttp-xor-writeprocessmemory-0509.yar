rule TTP_XOR_WriteProcessMemory_0509 {
  strings:
    $key_0509 = { 52 7b [2] 60 59 [2] 66 6c [2] 48 6c [2] 77 70 }

  condition:
    any of them
}