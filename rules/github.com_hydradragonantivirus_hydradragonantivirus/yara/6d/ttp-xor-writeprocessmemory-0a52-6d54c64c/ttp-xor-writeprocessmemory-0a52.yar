rule TTP_XOR_WriteProcessMemory_0a52 {
  strings:
    $key_0a52 = { 5d 20 [2] 6f 02 [2] 69 37 [2] 47 37 [2] 78 2b }

  condition:
    any of them
}