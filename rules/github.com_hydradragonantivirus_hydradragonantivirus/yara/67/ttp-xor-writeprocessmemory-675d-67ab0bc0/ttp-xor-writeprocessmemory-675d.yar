rule TTP_XOR_WriteProcessMemory_675d {
  strings:
    $key_675d = { 30 2f [2] 02 0d [2] 04 38 [2] 2a 38 [2] 15 24 }

  condition:
    any of them
}