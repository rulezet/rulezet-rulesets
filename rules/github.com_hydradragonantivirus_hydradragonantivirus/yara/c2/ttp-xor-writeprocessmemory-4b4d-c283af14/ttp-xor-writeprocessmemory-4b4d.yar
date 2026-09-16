rule TTP_XOR_WriteProcessMemory_4b4d {
  strings:
    $key_4b4d = { 1c 3f [2] 2e 1d [2] 28 28 [2] 06 28 [2] 39 34 }

  condition:
    any of them
}