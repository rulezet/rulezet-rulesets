rule TTP_XOR_WriteProcessMemory_272d {
  strings:
    $key_272d = { 70 5f [2] 42 7d [2] 44 48 [2] 6a 48 [2] 55 54 }

  condition:
    any of them
}