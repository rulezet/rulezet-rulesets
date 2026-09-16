rule TTP_XOR_WriteProcessMemory_0d21 {
  strings:
    $key_0d21 = { 5a 53 [2] 68 71 [2] 6e 44 [2] 40 44 [2] 7f 58 }

  condition:
    any of them
}