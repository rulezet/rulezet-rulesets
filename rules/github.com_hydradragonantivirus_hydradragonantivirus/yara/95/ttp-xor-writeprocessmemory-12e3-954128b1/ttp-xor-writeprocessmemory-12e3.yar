rule TTP_XOR_WriteProcessMemory_12e3 {
  strings:
    $key_12e3 = { 45 91 [2] 77 b3 [2] 71 86 [2] 5f 86 [2] 60 9a }

  condition:
    any of them
}