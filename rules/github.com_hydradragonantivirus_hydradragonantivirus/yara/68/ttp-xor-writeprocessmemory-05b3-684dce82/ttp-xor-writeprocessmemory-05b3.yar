rule TTP_XOR_WriteProcessMemory_05b3 {
  strings:
    $key_05b3 = { 52 c1 [2] 60 e3 [2] 66 d6 [2] 48 d6 [2] 77 ca }

  condition:
    any of them
}