rule TTP_XOR_WriteProcessMemory_0da6 {
  strings:
    $key_0da6 = { 5a d4 [2] 68 f6 [2] 6e c3 [2] 40 c3 [2] 7f df }

  condition:
    any of them
}