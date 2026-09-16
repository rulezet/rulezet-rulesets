rule TTP_XOR_WriteProcessMemory_560d {
  strings:
    $key_560d = { 01 7f [2] 33 5d [2] 35 68 [2] 1b 68 [2] 24 74 }

  condition:
    any of them
}