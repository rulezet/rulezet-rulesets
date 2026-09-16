rule TTP_XOR_WriteProcessMemory_1e37 {
  strings:
    $key_1e37 = { 49 45 [2] 7b 67 [2] 7d 52 [2] 53 52 [2] 6c 4e }

  condition:
    any of them
}