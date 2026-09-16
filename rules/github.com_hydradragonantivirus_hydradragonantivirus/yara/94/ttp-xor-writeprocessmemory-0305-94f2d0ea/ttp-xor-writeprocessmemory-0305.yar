rule TTP_XOR_WriteProcessMemory_0305 {
  strings:
    $key_0305 = { 54 77 [2] 66 55 [2] 60 60 [2] 4e 60 [2] 71 7c }

  condition:
    any of them
}