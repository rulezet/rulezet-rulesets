rule TTP_XOR_WriteProcessMemory_3841 {
  strings:
    $key_3841 = { 6f 33 [2] 5d 11 [2] 5b 24 [2] 75 24 [2] 4a 38 }

  condition:
    any of them
}