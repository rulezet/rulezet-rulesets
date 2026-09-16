rule TTP_XOR_WriteProcessMemory_094d {
  strings:
    $key_094d = { 5e 3f [2] 6c 1d [2] 6a 28 [2] 44 28 [2] 7b 34 }

  condition:
    any of them
}