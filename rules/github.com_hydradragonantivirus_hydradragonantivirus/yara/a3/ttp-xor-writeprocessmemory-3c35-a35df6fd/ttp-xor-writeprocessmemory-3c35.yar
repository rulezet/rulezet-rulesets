rule TTP_XOR_WriteProcessMemory_3c35 {
  strings:
    $key_3c35 = { 6b 47 [2] 59 65 [2] 5f 50 [2] 71 50 [2] 4e 4c }

  condition:
    any of them
}