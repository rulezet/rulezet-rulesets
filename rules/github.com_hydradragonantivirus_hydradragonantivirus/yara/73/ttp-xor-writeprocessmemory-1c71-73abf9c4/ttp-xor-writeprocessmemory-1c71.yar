rule TTP_XOR_WriteProcessMemory_1c71 {
  strings:
    $key_1c71 = { 4b 03 [2] 79 21 [2] 7f 14 [2] 51 14 [2] 6e 08 }

  condition:
    any of them
}