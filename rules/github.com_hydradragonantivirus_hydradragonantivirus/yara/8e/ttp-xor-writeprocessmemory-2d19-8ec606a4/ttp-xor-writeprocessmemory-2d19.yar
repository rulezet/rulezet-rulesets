rule TTP_XOR_WriteProcessMemory_2d19 {
  strings:
    $key_2d19 = { 7a 6b [2] 48 49 [2] 4e 7c [2] 60 7c [2] 5f 60 }

  condition:
    any of them
}