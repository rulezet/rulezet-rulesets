rule TTP_XOR_WriteProcessMemory_2855 {
  strings:
    $key_2855 = { 7f 27 [2] 4d 05 [2] 4b 30 [2] 65 30 [2] 5a 2c }

  condition:
    any of them
}