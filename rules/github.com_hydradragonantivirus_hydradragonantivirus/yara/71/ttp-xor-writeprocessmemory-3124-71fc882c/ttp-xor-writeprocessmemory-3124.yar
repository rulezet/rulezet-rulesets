rule TTP_XOR_WriteProcessMemory_3124 {
  strings:
    $key_3124 = { 66 56 [2] 54 74 [2] 52 41 [2] 7c 41 [2] 43 5d }

  condition:
    any of them
}