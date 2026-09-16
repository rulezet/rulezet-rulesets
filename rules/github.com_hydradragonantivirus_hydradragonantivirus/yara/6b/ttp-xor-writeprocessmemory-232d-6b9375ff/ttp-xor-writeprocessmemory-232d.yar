rule TTP_XOR_WriteProcessMemory_232d {
  strings:
    $key_232d = { 74 5f [2] 46 7d [2] 40 48 [2] 6e 48 [2] 51 54 }

  condition:
    any of them
}