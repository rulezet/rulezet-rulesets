rule TTP_XOR_WriteProcessMemory_7e3f {
  strings:
    $key_7e3f = { 29 4d [2] 1b 6f [2] 1d 5a [2] 33 5a [2] 0c 46 }

  condition:
    any of them
}