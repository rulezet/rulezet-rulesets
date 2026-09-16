rule TTP_XOR_WriteProcessMemory_762d {
  strings:
    $key_762d = { 21 5f [2] 13 7d [2] 15 48 [2] 3b 48 [2] 04 54 }

  condition:
    any of them
}