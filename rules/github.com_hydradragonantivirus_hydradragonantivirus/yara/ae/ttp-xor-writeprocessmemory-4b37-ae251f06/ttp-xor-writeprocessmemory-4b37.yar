rule TTP_XOR_WriteProcessMemory_4b37 {
  strings:
    $key_4b37 = { 1c 45 [2] 2e 67 [2] 28 52 [2] 06 52 [2] 39 4e }

  condition:
    any of them
}