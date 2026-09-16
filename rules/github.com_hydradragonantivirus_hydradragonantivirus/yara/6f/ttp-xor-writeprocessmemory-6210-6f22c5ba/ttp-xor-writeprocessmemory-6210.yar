rule TTP_XOR_WriteProcessMemory_6210 {
  strings:
    $key_6210 = { 35 62 [2] 07 40 [2] 01 75 [2] 2f 75 [2] 10 69 }

  condition:
    any of them
}