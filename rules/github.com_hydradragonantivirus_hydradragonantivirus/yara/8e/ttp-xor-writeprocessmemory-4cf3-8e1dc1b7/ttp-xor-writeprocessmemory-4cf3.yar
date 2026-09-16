rule TTP_XOR_WriteProcessMemory_4cf3 {
  strings:
    $key_4cf3 = { 1b 81 [2] 29 a3 [2] 2f 96 [2] 01 96 [2] 3e 8a }

  condition:
    any of them
}