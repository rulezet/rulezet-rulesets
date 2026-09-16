rule TTP_XOR_WriteProcessMemory_3b0d {
  strings:
    $key_3b0d = { 6c 7f [2] 5e 5d [2] 58 68 [2] 76 68 [2] 49 74 }

  condition:
    any of them
}