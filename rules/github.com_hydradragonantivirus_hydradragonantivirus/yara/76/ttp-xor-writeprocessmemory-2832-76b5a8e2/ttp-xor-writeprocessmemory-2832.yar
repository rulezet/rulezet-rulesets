rule TTP_XOR_WriteProcessMemory_2832 {
  strings:
    $key_2832 = { 7f 40 [2] 4d 62 [2] 4b 57 [2] 65 57 [2] 5a 4b }

  condition:
    any of them
}