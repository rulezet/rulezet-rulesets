rule TTP_XOR_WriteProcessMemory_2611 {
  strings:
    $key_2611 = { 71 63 [2] 43 41 [2] 45 74 [2] 6b 74 [2] 54 68 }

  condition:
    any of them
}