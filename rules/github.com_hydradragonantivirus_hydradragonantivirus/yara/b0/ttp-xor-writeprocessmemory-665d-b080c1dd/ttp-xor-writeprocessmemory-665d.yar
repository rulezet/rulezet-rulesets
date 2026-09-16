rule TTP_XOR_WriteProcessMemory_665d {
  strings:
    $key_665d = { 31 2f [2] 03 0d [2] 05 38 [2] 2b 38 [2] 14 24 }

  condition:
    any of them
}