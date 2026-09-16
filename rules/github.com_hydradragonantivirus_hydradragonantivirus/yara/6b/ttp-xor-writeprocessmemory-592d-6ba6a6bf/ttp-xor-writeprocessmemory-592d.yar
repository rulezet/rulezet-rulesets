rule TTP_XOR_WriteProcessMemory_592d {
  strings:
    $key_592d = { 0e 5f [2] 3c 7d [2] 3a 48 [2] 14 48 [2] 2b 54 }

  condition:
    any of them
}