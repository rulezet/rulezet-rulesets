rule TTP_XOR_WriteProcessMemory_2821 {
  strings:
    $key_2821 = { 7f 53 [2] 4d 71 [2] 4b 44 [2] 65 44 [2] 5a 58 }

  condition:
    any of them
}