rule TTP_XOR_WriteProcessMemory_2808 {
  strings:
    $key_2808 = { 7f 7a [2] 4d 58 [2] 4b 6d [2] 65 6d [2] 5a 71 }

  condition:
    any of them
}