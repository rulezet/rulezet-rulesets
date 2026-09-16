rule TTP_XOR_WriteProcessMemory_69e6 {
  strings:
    $key_69e6 = { 3e 94 [2] 0c b6 [2] 0a 83 [2] 24 83 [2] 1b 9f }

  condition:
    any of them
}