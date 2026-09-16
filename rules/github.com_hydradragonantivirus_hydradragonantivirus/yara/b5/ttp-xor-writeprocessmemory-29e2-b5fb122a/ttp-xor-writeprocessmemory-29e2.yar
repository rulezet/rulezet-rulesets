rule TTP_XOR_WriteProcessMemory_29e2 {
  strings:
    $key_29e2 = { 7e 90 [2] 4c b2 [2] 4a 87 [2] 64 87 [2] 5b 9b }

  condition:
    any of them
}