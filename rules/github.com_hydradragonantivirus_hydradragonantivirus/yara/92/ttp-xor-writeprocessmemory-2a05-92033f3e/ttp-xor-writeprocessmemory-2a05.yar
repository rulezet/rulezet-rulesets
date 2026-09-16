rule TTP_XOR_WriteProcessMemory_2a05 {
  strings:
    $key_2a05 = { 7d 77 [2] 4f 55 [2] 49 60 [2] 67 60 [2] 58 7c }

  condition:
    any of them
}