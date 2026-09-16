rule TTP_XOR_WriteProcessMemory_2019 {
  strings:
    $key_2019 = { 77 6b [2] 45 49 [2] 43 7c [2] 6d 7c [2] 52 60 }

  condition:
    any of them
}