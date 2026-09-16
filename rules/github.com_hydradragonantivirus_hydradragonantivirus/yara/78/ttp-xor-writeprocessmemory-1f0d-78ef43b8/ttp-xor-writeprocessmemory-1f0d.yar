rule TTP_XOR_WriteProcessMemory_1f0d {
  strings:
    $key_1f0d = { 48 7f [2] 7a 5d [2] 7c 68 [2] 52 68 [2] 6d 74 }

  condition:
    any of them
}