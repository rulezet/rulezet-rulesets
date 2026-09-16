rule TTP_XOR_WriteProcessMemory_0452 {
  strings:
    $key_0452 = { 53 20 [2] 61 02 [2] 67 37 [2] 49 37 [2] 76 2b }

  condition:
    any of them
}