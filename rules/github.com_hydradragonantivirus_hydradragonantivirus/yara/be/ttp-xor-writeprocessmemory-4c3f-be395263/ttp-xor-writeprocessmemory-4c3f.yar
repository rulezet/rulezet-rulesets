rule TTP_XOR_WriteProcessMemory_4c3f {
  strings:
    $key_4c3f = { 1b 4d [2] 29 6f [2] 2f 5a [2] 01 5a [2] 3e 46 }

  condition:
    any of them
}