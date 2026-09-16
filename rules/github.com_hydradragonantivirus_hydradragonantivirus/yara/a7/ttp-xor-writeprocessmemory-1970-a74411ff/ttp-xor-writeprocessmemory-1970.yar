rule TTP_XOR_WriteProcessMemory_1970 {
  strings:
    $key_1970 = { 4e 02 [2] 7c 20 [2] 7a 15 [2] 54 15 [2] 6b 09 }

  condition:
    any of them
}