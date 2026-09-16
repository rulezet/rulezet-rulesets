rule TTP_XOR_WriteProcessMemory_0205 {
  strings:
    $key_0205 = { 55 77 [2] 67 55 [2] 61 60 [2] 4f 60 [2] 70 7c }

  condition:
    any of them
}