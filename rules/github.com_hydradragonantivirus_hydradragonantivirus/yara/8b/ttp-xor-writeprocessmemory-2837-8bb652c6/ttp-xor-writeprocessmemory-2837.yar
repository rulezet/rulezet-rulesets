rule TTP_XOR_WriteProcessMemory_2837 {
  strings:
    $key_2837 = { 7f 45 [2] 4d 67 [2] 4b 52 [2] 65 52 [2] 5a 4e }

  condition:
    any of them
}