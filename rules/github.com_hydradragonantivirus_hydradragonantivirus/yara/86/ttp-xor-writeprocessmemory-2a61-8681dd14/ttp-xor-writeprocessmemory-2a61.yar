rule TTP_XOR_WriteProcessMemory_2a61 {
  strings:
    $key_2a61 = { 7d 13 [2] 4f 31 [2] 49 04 [2] 67 04 [2] 58 18 }

  condition:
    any of them
}