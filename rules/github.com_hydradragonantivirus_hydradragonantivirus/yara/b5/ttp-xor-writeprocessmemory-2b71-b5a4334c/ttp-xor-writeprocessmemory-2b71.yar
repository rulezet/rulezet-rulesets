rule TTP_XOR_WriteProcessMemory_2b71 {
  strings:
    $key_2b71 = { 7c 03 [2] 4e 21 [2] 48 14 [2] 66 14 [2] 59 08 }

  condition:
    any of them
}