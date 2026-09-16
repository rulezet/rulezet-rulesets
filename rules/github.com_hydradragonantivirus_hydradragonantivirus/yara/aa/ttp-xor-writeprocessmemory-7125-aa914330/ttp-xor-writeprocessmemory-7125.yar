rule TTP_XOR_WriteProcessMemory_7125 {
  strings:
    $key_7125 = { 26 57 [2] 14 75 [2] 12 40 [2] 3c 40 [2] 03 5c }

  condition:
    any of them
}