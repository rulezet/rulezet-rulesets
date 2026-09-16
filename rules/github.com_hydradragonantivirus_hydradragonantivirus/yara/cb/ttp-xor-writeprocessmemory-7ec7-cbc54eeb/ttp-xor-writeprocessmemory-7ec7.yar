rule TTP_XOR_WriteProcessMemory_7ec7 {
  strings:
    $key_7ec7 = { 29 b5 [2] 1b 97 [2] 1d a2 [2] 33 a2 [2] 0c be }

  condition:
    any of them
}