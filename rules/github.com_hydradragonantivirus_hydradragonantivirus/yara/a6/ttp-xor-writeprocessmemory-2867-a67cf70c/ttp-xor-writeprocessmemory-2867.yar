rule TTP_XOR_WriteProcessMemory_2867 {
  strings:
    $key_2867 = { 7f 15 [2] 4d 37 [2] 4b 02 [2] 65 02 [2] 5a 1e }

  condition:
    any of them
}