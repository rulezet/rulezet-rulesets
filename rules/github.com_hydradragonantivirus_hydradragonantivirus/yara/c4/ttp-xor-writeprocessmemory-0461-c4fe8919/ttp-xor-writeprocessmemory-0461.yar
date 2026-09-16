rule TTP_XOR_WriteProcessMemory_0461 {
  strings:
    $key_0461 = { 53 13 [2] 61 31 [2] 67 04 [2] 49 04 [2] 76 18 }

  condition:
    any of them
}