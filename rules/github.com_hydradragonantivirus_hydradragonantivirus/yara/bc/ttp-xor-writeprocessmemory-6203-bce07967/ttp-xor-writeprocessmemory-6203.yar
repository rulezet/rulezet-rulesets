rule TTP_XOR_WriteProcessMemory_6203 {
  strings:
    $key_6203 = { 35 71 [2] 07 53 [2] 01 66 [2] 2f 66 [2] 10 7a }

  condition:
    any of them
}