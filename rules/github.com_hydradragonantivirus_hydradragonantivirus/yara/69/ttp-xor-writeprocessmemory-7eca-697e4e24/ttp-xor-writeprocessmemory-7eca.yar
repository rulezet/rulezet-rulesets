rule TTP_XOR_WriteProcessMemory_7eca {
  strings:
    $key_7eca = { 29 b8 [2] 1b 9a [2] 1d af [2] 33 af [2] 0c b3 }

  condition:
    any of them
}