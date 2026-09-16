rule TTP_XOR_WriteProcessMemory_2825 {
  strings:
    $key_2825 = { 7f 57 [2] 4d 75 [2] 4b 40 [2] 65 40 [2] 5a 5c }

  condition:
    any of them
}