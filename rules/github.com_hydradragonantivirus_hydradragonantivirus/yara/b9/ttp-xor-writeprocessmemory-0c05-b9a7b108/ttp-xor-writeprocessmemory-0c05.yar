rule TTP_XOR_WriteProcessMemory_0c05 {
  strings:
    $key_0c05 = { 5b 77 [2] 69 55 [2] 6f 60 [2] 41 60 [2] 7e 7c }

  condition:
    any of them
}