rule TTP_XOR_WriteProcessMemory_3539 {
  strings:
    $key_3539 = { 62 4b [2] 50 69 [2] 56 5c [2] 78 5c [2] 47 40 }

  condition:
    any of them
}