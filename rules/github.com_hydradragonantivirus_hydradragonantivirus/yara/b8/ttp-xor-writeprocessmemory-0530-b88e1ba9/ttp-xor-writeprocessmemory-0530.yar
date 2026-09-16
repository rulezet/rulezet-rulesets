rule TTP_XOR_WriteProcessMemory_0530 {
  strings:
    $key_0530 = { 52 42 [2] 60 60 [2] 66 55 [2] 48 55 [2] 77 49 }

  condition:
    any of them
}