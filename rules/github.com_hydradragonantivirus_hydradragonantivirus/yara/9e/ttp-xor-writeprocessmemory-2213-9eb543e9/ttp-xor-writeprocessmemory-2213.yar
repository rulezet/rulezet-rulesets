rule TTP_XOR_WriteProcessMemory_2213 {
  strings:
    $key_2213 = { 75 61 [2] 47 43 [2] 41 76 [2] 6f 76 [2] 50 6a }

  condition:
    any of them
}