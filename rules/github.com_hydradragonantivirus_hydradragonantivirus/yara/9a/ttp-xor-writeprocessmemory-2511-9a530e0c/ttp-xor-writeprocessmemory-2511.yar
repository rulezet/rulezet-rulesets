rule TTP_XOR_WriteProcessMemory_2511 {
  strings:
    $key_2511 = { 72 63 [2] 40 41 [2] 46 74 [2] 68 74 [2] 57 68 }

  condition:
    any of them
}