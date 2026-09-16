rule TTP_XOR_WriteProcessMemory_761d {
  strings:
    $key_761d = { 21 6f [2] 13 4d [2] 15 78 [2] 3b 78 [2] 04 64 }

  condition:
    any of them
}