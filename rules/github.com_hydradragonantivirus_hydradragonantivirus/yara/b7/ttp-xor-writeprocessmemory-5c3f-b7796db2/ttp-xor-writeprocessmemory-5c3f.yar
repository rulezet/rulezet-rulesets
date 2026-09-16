rule TTP_XOR_WriteProcessMemory_5c3f {
  strings:
    $key_5c3f = { 0b 4d [2] 39 6f [2] 3f 5a [2] 11 5a [2] 2e 46 }

  condition:
    any of them
}