rule TTP_XOR_WriteProcessMemory_2816 {
  strings:
    $key_2816 = { 7f 64 [2] 4d 46 [2] 4b 73 [2] 65 73 [2] 5a 6f }

  condition:
    any of them
}