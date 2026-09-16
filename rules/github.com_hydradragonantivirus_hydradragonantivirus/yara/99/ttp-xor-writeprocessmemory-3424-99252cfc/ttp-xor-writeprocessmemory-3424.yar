rule TTP_XOR_WriteProcessMemory_3424 {
  strings:
    $key_3424 = { 63 56 [2] 51 74 [2] 57 41 [2] 79 41 [2] 46 5d }

  condition:
    any of them
}