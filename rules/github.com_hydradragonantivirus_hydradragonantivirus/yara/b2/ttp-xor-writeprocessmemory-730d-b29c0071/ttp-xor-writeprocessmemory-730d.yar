rule TTP_XOR_WriteProcessMemory_730d {
  strings:
    $key_730d = { 24 7f [2] 16 5d [2] 10 68 [2] 3e 68 [2] 01 74 }

  condition:
    any of them
}