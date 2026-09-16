rule TTP_XOR_WriteProcessMemory_693f {
  strings:
    $key_693f = { 3e 4d [2] 0c 6f [2] 0a 5a [2] 24 5a [2] 1b 46 }

  condition:
    any of them
}