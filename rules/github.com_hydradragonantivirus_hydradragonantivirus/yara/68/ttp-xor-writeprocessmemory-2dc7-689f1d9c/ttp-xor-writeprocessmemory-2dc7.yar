rule TTP_XOR_WriteProcessMemory_2dc7 {
  strings:
    $key_2dc7 = { 7a b5 [2] 48 97 [2] 4e a2 [2] 60 a2 [2] 5f be }

  condition:
    any of them
}