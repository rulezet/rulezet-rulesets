rule TTP_XOR_WriteProcessMemory_3163 {
  strings:
    $key_3163 = { 66 11 [2] 54 33 [2] 52 06 [2] 7c 06 [2] 43 1a }

  condition:
    any of them
}