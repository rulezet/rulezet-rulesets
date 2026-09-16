rule TTP_XOR_WriteProcessMemory_2ec7 {
  strings:
    $key_2ec7 = { 79 b5 [2] 4b 97 [2] 4d a2 [2] 63 a2 [2] 5c be }

  condition:
    any of them
}