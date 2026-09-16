rule TTP_XOR_WriteProcessMemory_442d {
  strings:
    $key_442d = { 13 5f [2] 21 7d [2] 27 48 [2] 09 48 [2] 36 54 }

  condition:
    any of them
}