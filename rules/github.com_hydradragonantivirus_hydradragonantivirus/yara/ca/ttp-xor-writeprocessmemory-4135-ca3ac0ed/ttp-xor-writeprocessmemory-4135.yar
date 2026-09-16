rule TTP_XOR_WriteProcessMemory_4135 {
  strings:
    $key_4135 = { 16 47 [2] 24 65 [2] 22 50 [2] 0c 50 [2] 33 4c }

  condition:
    any of them
}