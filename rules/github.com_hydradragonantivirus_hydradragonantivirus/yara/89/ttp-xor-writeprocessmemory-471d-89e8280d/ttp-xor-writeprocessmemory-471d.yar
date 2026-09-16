rule TTP_XOR_WriteProcessMemory_471d {
  strings:
    $key_471d = { 10 6f [2] 22 4d [2] 24 78 [2] 0a 78 [2] 35 64 }

  condition:
    any of them
}