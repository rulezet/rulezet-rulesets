rule TTP_XOR_WriteProcessMemory_283d {
  strings:
    $key_283d = { 7f 4f [2] 4d 6d [2] 4b 58 [2] 65 58 [2] 5a 44 }

  condition:
    any of them
}