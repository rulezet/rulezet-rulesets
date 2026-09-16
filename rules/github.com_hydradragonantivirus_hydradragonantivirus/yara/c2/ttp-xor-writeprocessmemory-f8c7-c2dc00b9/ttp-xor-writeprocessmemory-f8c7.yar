rule TTP_XOR_WriteProcessMemory_f8c7 {
  strings:
    $key_f8c7 = { af b5 [2] 9d 97 [2] 9b a2 [2] b5 a2 [2] 8a be }

  condition:
    any of them
}