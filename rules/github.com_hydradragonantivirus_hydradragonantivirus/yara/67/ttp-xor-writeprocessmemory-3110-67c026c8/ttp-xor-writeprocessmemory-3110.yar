rule TTP_XOR_WriteProcessMemory_3110 {
  strings:
    $key_3110 = { 66 62 [2] 54 40 [2] 52 75 [2] 7c 75 [2] 43 69 }

  condition:
    any of them
}