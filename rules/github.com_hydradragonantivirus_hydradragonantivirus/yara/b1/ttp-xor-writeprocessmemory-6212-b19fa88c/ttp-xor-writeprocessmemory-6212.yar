rule TTP_XOR_WriteProcessMemory_6212 {
  strings:
    $key_6212 = { 35 60 [2] 07 42 [2] 01 77 [2] 2f 77 [2] 10 6b }

  condition:
    any of them
}