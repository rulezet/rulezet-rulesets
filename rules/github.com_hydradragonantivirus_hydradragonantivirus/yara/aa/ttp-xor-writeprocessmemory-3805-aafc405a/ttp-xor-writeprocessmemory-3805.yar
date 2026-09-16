rule TTP_XOR_WriteProcessMemory_3805 {
  strings:
    $key_3805 = { 6f 77 [2] 5d 55 [2] 5b 60 [2] 75 60 [2] 4a 7c }

  condition:
    any of them
}