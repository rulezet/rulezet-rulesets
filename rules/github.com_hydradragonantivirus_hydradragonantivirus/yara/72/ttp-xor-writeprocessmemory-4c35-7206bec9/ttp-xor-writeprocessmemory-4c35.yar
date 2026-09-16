rule TTP_XOR_WriteProcessMemory_4c35 {
  strings:
    $key_4c35 = { 1b 47 [2] 29 65 [2] 2f 50 [2] 01 50 [2] 3e 4c }

  condition:
    any of them
}