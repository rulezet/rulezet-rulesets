rule TTP_XOR_WriteProcessMemory_294d {
  strings:
    $key_294d = { 7e 3f [2] 4c 1d [2] 4a 28 [2] 64 28 [2] 5b 34 }

  condition:
    any of them
}