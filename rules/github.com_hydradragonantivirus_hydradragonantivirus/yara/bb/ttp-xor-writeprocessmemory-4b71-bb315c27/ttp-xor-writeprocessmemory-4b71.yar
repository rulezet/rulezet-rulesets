rule TTP_XOR_WriteProcessMemory_4b71 {
  strings:
    $key_4b71 = { 1c 03 [2] 2e 21 [2] 28 14 [2] 06 14 [2] 39 08 }

  condition:
    any of them
}