rule TTP_XOR_WriteProcessMemory_1430 {
  strings:
    $key_1430 = { 43 42 [2] 71 60 [2] 77 55 [2] 59 55 [2] 66 49 }

  condition:
    any of them
}