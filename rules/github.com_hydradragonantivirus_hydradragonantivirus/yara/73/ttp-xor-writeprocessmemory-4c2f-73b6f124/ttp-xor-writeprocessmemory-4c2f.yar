rule TTP_XOR_WriteProcessMemory_4c2f {
  strings:
    $key_4c2f = { 1b 5d [2] 29 7f [2] 2f 4a [2] 01 4a [2] 3e 56 }

  condition:
    any of them
}