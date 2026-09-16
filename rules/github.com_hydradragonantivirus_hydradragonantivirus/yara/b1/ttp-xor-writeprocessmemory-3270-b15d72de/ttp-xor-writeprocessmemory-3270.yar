rule TTP_XOR_WriteProcessMemory_3270 {
  strings:
    $key_3270 = { 65 02 [2] 57 20 [2] 51 15 [2] 7f 15 [2] 40 09 }

  condition:
    any of them
}