rule TTP_XOR_WriteProcessMemory_14b3 {
  strings:
    $key_14b3 = { 43 c1 [2] 71 e3 [2] 77 d6 [2] 59 d6 [2] 66 ca }

  condition:
    any of them
}