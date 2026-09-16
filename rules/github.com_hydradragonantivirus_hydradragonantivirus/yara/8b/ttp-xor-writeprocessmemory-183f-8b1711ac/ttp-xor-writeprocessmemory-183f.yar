rule TTP_XOR_WriteProcessMemory_183f {
  strings:
    $key_183f = { 4f 4d [2] 7d 6f [2] 7b 5a [2] 55 5a [2] 6a 46 }

  condition:
    any of them
}