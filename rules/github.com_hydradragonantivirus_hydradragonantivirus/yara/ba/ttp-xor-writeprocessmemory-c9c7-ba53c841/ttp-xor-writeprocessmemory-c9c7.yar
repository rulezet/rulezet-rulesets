rule TTP_XOR_WriteProcessMemory_c9c7 {
  strings:
    $key_c9c7 = { 9e b5 [2] ac 97 [2] aa a2 [2] 84 a2 [2] bb be }

  condition:
    any of them
}