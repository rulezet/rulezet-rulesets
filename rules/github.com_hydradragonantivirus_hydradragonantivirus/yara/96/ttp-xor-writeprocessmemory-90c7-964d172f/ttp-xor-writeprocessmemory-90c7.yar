rule TTP_XOR_WriteProcessMemory_90c7 {
  strings:
    $key_90c7 = { c7 b5 [2] f5 97 [2] f3 a2 [2] dd a2 [2] e2 be }

  condition:
    any of them
}