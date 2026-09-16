rule TTP_XOR_WriteProcessMemory_4a19 {
  strings:
    $key_4a19 = { 1d 6b [2] 2f 49 [2] 29 7c [2] 07 7c [2] 38 60 }

  condition:
    any of them
}