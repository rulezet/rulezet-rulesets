rule TTP_XOR_WriteProcessMemory_5213 {
  strings:
    $key_5213 = { 05 61 [2] 37 43 [2] 31 76 [2] 1f 76 [2] 20 6a }

  condition:
    any of them
}