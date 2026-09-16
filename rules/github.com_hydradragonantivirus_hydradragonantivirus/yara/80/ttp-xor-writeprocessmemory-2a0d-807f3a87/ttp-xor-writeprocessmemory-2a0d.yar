rule TTP_XOR_WriteProcessMemory_2a0d {
  strings:
    $key_2a0d = { 7d 7f [2] 4f 5d [2] 49 68 [2] 67 68 [2] 58 74 }

  condition:
    any of them
}