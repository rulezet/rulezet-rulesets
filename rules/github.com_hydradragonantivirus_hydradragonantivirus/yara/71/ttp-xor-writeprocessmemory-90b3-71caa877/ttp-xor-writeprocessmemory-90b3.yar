rule TTP_XOR_WriteProcessMemory_90b3 {
  strings:
    $key_90b3 = { c7 c1 [2] f5 e3 [2] f3 d6 [2] dd d6 [2] e2 ca }

  condition:
    any of them
}