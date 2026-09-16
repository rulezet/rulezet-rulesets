rule TTP_XOR_WriteProcessMemory_195d {
  strings:
    $key_195d = { 4e 2f [2] 7c 0d [2] 7a 38 [2] 54 38 [2] 6b 24 }

  condition:
    any of them
}