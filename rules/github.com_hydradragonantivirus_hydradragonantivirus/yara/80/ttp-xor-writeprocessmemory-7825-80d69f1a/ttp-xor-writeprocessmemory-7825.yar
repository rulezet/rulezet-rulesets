rule TTP_XOR_WriteProcessMemory_7825 {
  strings:
    $key_7825 = { 2f 57 [2] 1d 75 [2] 1b 40 [2] 35 40 [2] 0a 5c }

  condition:
    any of them
}