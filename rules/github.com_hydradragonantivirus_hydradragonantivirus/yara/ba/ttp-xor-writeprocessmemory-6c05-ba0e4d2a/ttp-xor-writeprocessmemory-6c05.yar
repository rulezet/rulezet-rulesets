rule TTP_XOR_WriteProcessMemory_6c05 {
  strings:
    $key_6c05 = { 3b 77 [2] 09 55 [2] 0f 60 [2] 21 60 [2] 1e 7c }

  condition:
    any of them
}