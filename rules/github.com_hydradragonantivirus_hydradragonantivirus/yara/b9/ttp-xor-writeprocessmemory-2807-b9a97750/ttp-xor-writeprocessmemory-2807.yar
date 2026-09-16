rule TTP_XOR_WriteProcessMemory_2807 {
  strings:
    $key_2807 = { 7f 75 [2] 4d 57 [2] 4b 62 [2] 65 62 [2] 5a 7e }

  condition:
    any of them
}