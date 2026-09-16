rule TTP_XOR_WriteProcessMemory_14e3 {
  strings:
    $key_14e3 = { 43 91 [2] 71 b3 [2] 77 86 [2] 59 86 [2] 66 9a }

  condition:
    any of them
}