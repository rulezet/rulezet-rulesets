rule TTP_XOR_WriteProcessMemory_790d {
  strings:
    $key_790d = { 2e 7f [2] 1c 5d [2] 1a 68 [2] 34 68 [2] 0b 74 }

  condition:
    any of them
}