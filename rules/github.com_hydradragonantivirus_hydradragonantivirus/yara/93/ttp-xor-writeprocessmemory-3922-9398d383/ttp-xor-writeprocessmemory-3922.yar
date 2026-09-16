rule TTP_XOR_WriteProcessMemory_3922 {
  strings:
    $key_3922 = { 6e 50 [2] 5c 72 [2] 5a 47 [2] 74 47 [2] 4b 5b }

  condition:
    any of them
}