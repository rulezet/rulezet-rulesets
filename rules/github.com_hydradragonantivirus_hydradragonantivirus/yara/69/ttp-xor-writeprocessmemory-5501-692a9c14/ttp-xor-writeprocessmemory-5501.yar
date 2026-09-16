rule TTP_XOR_WriteProcessMemory_5501 {
  strings:
    $key_5501 = { 02 73 [2] 30 51 [2] 36 64 [2] 18 64 [2] 27 78 }

  condition:
    any of them
}