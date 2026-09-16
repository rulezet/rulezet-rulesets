rule TTP_XOR_WriteProcessMemory_3857 {
  strings:
    $key_3857 = { 6f 25 [2] 5d 07 [2] 5b 32 [2] 75 32 [2] 4a 2e }

  condition:
    any of them
}