rule TTP_XOR_WriteProcessMemory_1922 {
  strings:
    $key_1922 = { 4e 50 [2] 7c 72 [2] 7a 47 [2] 54 47 [2] 6b 5b }

  condition:
    any of them
}