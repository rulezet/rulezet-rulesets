rule TTP_XOR_WriteProcessMemory_7816 {
  strings:
    $key_7816 = { 2f 64 [2] 1d 46 [2] 1b 73 [2] 35 73 [2] 0a 6f }

  condition:
    any of them
}