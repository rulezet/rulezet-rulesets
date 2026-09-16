rule TTP_XOR_WriteProcessMemory_1dc7 {
  strings:
    $key_1dc7 = { 4a b5 [2] 78 97 [2] 7e a2 [2] 50 a2 [2] 6f be }

  condition:
    any of them
}