rule TTP_XOR_WriteProcessMemory_1209 {
  strings:
    $key_1209 = { 45 7b [2] 77 59 [2] 71 6c [2] 5f 6c [2] 60 70 }

  condition:
    any of them
}