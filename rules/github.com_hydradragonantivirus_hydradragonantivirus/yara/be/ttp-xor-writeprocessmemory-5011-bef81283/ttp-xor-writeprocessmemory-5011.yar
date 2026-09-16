rule TTP_XOR_WriteProcessMemory_5011 {
  strings:
    $key_5011 = { 07 63 [2] 35 41 [2] 33 74 [2] 1d 74 [2] 22 68 }

  condition:
    any of them
}