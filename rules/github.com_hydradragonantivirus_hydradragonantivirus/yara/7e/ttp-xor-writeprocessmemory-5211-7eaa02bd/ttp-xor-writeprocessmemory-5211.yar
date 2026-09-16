rule TTP_XOR_WriteProcessMemory_5211 {
  strings:
    $key_5211 = { 05 63 [2] 37 41 [2] 31 74 [2] 1f 74 [2] 20 68 }

  condition:
    any of them
}