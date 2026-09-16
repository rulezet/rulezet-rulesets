rule TTP_XOR_WriteProcessMemory_0d71 {
  strings:
    $key_0d71 = { 5a 03 [2] 68 21 [2] 6e 14 [2] 40 14 [2] 7f 08 }

  condition:
    any of them
}