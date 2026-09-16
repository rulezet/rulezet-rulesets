rule TTP_XOR_WriteProcessMemory_192f {
  strings:
    $key_192f = { 4e 5d [2] 7c 7f [2] 7a 4a [2] 54 4a [2] 6b 56 }

  condition:
    any of them
}