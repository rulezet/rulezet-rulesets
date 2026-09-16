rule TTP_XOR_WriteProcessMemory_f9c7 {
  strings:
    $key_f9c7 = { ae b5 [2] 9c 97 [2] 9a a2 [2] b4 a2 [2] 8b be }

  condition:
    any of them
}