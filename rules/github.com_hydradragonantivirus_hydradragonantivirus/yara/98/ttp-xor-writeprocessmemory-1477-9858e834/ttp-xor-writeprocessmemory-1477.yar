rule TTP_XOR_WriteProcessMemory_1477 {
  strings:
    $key_1477 = { 43 05 [2] 71 27 [2] 77 12 [2] 59 12 [2] 66 0e }

  condition:
    any of them
}