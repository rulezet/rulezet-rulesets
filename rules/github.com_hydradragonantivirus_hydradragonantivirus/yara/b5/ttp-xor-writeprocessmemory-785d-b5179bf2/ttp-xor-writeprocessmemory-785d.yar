rule TTP_XOR_WriteProcessMemory_785d {
  strings:
    $key_785d = { 2f 2f [2] 1d 0d [2] 1b 38 [2] 35 38 [2] 0a 24 }

  condition:
    any of them
}