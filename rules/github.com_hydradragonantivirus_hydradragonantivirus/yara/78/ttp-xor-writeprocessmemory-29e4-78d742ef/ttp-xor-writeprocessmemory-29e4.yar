rule TTP_XOR_WriteProcessMemory_29e4 {
  strings:
    $key_29e4 = { 7e 96 [2] 4c b4 [2] 4a 81 [2] 64 81 [2] 5b 9d }

  condition:
    any of them
}