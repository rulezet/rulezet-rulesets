rule TTP_XOR_WriteProcessMemory_4aa3 {
  strings:
    $key_4aa3 = { 1d d1 [2] 2f f3 [2] 29 c6 [2] 07 c6 [2] 38 da }

  condition:
    any of them
}