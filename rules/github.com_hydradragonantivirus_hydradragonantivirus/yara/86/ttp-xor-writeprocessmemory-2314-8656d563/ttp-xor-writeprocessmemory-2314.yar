rule TTP_XOR_WriteProcessMemory_2314 {
  strings:
    $key_2314 = { 74 66 [2] 46 44 [2] 40 71 [2] 6e 71 [2] 51 6d }

  condition:
    any of them
}