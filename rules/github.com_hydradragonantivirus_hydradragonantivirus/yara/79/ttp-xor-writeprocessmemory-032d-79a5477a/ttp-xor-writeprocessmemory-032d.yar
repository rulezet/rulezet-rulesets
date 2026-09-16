rule TTP_XOR_WriteProcessMemory_032d {
  strings:
    $key_032d = { 54 5f [2] 66 7d [2] 60 48 [2] 4e 48 [2] 71 54 }

  condition:
    any of them
}