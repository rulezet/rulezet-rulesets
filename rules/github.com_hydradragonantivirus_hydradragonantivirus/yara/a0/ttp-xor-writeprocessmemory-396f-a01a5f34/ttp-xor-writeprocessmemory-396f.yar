rule TTP_XOR_WriteProcessMemory_396f {
  strings:
    $key_396f = { 6e 1d [2] 5c 3f [2] 5a 0a [2] 74 0a [2] 4b 16 }

  condition:
    any of them
}