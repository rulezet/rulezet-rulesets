rule TTP_XOR_WriteProcessMemory_2539 {
  strings:
    $key_2539 = { 72 4b [2] 40 69 [2] 46 5c [2] 68 5c [2] 57 40 }

  condition:
    any of them
}