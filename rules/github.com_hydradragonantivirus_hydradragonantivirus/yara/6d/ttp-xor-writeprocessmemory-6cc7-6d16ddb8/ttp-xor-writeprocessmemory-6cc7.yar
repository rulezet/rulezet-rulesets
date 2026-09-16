rule TTP_XOR_WriteProcessMemory_6cc7 {
  strings:
    $key_6cc7 = { 3b b5 [2] 09 97 [2] 0f a2 [2] 21 a2 [2] 1e be }

  condition:
    any of them
}