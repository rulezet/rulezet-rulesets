rule TTP_XOR_WriteProcessMemory_4486 {
  strings:
    $key_4486 = { 13 f4 [2] 21 d6 [2] 27 e3 [2] 09 e3 [2] 36 ff }

  condition:
    any of them
}