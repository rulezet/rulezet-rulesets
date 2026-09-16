rule TTP_XOR_WriteProcessMemory_6b0d {
  strings:
    $key_6b0d = { 3c 7f [2] 0e 5d [2] 08 68 [2] 26 68 [2] 19 74 }

  condition:
    any of them
}