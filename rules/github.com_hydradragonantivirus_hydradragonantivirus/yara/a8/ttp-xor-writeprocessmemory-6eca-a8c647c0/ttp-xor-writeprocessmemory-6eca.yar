rule TTP_XOR_WriteProcessMemory_6eca {
  strings:
    $key_6eca = { 39 b8 [2] 0b 9a [2] 0d af [2] 23 af [2] 1c b3 }

  condition:
    any of them
}