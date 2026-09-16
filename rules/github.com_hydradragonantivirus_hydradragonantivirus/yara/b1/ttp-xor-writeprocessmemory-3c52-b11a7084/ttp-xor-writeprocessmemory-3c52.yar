rule TTP_XOR_WriteProcessMemory_3c52 {
  strings:
    $key_3c52 = { 6b 20 [2] 59 02 [2] 5f 37 [2] 71 37 [2] 4e 2b }

  condition:
    any of them
}