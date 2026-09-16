rule TTP_XOR_WriteProcessMemory_6937 {
  strings:
    $key_6937 = { 3e 45 [2] 0c 67 [2] 0a 52 [2] 24 52 [2] 1b 4e }

  condition:
    any of them
}