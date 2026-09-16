rule TTP_XOR_WriteProcessMemory_7f0d {
  strings:
    $key_7f0d = { 28 7f [2] 1a 5d [2] 1c 68 [2] 32 68 [2] 0d 74 }

  condition:
    any of them
}