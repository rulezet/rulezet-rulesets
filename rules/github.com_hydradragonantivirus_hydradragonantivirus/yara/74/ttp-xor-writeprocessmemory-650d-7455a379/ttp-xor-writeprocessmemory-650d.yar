rule TTP_XOR_WriteProcessMemory_650d {
  strings:
    $key_650d = { 32 7f [2] 00 5d [2] 06 68 [2] 28 68 [2] 17 74 }

  condition:
    any of them
}