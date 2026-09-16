rule TTP_XOR_WriteProcessMemory_4c1f {
  strings:
    $key_4c1f = { 1b 6d [2] 29 4f [2] 2f 7a [2] 01 7a [2] 3e 66 }

  condition:
    any of them
}