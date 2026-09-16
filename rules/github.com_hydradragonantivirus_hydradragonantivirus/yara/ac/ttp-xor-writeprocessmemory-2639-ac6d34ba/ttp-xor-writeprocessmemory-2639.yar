rule TTP_XOR_WriteProcessMemory_2639 {
  strings:
    $key_2639 = { 71 4b [2] 43 69 [2] 45 5c [2] 6b 5c [2] 54 40 }

  condition:
    any of them
}