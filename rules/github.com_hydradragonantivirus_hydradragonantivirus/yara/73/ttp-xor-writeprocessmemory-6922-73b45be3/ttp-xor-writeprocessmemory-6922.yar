rule TTP_XOR_WriteProcessMemory_6922 {
  strings:
    $key_6922 = { 3e 50 [2] 0c 72 [2] 0a 47 [2] 24 47 [2] 1b 5b }

  condition:
    any of them
}