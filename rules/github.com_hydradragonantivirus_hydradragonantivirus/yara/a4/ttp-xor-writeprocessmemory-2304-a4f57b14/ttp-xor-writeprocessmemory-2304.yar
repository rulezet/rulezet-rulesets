rule TTP_XOR_WriteProcessMemory_2304 {
  strings:
    $key_2304 = { 74 76 [2] 46 54 [2] 40 61 [2] 6e 61 [2] 51 7d }

  condition:
    any of them
}