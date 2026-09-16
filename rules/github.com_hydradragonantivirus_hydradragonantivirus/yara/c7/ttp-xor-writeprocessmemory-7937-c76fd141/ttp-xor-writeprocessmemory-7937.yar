rule TTP_XOR_WriteProcessMemory_7937 {
  strings:
    $key_7937 = { 2e 45 [2] 1c 67 [2] 1a 52 [2] 34 52 [2] 0b 4e }

  condition:
    any of them
}