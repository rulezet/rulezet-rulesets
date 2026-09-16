rule TTP_XOR_WriteProcessMemory_5d2f {
  strings:
    $key_5d2f = { 0a 5d [2] 38 7f [2] 3e 4a [2] 10 4a [2] 2f 56 }

  condition:
    any of them
}