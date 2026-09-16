rule TTP_XOR_WriteProcessMemory_2211 {
  strings:
    $key_2211 = { 75 63 [2] 47 41 [2] 41 74 [2] 6f 74 [2] 50 68 }

  condition:
    any of them
}