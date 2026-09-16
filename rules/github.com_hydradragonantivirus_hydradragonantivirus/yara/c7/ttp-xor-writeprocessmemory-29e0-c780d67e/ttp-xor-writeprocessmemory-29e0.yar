rule TTP_XOR_WriteProcessMemory_29e0 {
  strings:
    $key_29e0 = { 7e 92 [2] 4c b0 [2] 4a 85 [2] 64 85 [2] 5b 99 }

  condition:
    any of them
}