rule TTP_XOR_WriteProcessMemory_765d {
  strings:
    $key_765d = { 21 2f [2] 13 0d [2] 15 38 [2] 3b 38 [2] 04 24 }

  condition:
    any of them
}