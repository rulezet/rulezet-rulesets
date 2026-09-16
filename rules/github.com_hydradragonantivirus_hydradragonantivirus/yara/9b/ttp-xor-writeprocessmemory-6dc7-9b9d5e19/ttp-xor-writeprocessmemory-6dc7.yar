rule TTP_XOR_WriteProcessMemory_6dc7 {
  strings:
    $key_6dc7 = { 3a b5 [2] 08 97 [2] 0e a2 [2] 20 a2 [2] 1f be }

  condition:
    any of them
}