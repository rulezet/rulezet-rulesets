rule TTP_XOR_WriteProcessMemory_6f37 {
  strings:
    $key_6f37 = { 38 45 [2] 0a 67 [2] 0c 52 [2] 22 52 [2] 1d 4e }

  condition:
    any of them
}