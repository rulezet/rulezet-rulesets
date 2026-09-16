rule TTP_XOR_WriteProcessMemory_2659 {
  strings:
    $key_2659 = { 71 2b [2] 43 09 [2] 45 3c [2] 6b 3c [2] 54 20 }

  condition:
    any of them
}