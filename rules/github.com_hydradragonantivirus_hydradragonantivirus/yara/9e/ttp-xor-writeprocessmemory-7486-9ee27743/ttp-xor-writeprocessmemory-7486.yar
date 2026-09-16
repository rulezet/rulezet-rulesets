rule TTP_XOR_WriteProcessMemory_7486 {
  strings:
    $key_7486 = { 23 f4 [2] 11 d6 [2] 17 e3 [2] 39 e3 [2] 06 ff }

  condition:
    any of them
}