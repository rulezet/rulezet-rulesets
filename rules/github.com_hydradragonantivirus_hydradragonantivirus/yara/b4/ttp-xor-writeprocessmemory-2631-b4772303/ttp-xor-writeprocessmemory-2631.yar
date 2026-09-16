rule TTP_XOR_WriteProcessMemory_2631 {
  strings:
    $key_2631 = { 71 43 [2] 43 61 [2] 45 54 [2] 6b 54 [2] 54 48 }

  condition:
    any of them
}