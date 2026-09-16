rule TTP_XOR_WriteProcessMemory_6e3f {
  strings:
    $key_6e3f = { 39 4d [2] 0b 6f [2] 0d 5a [2] 23 5a [2] 1c 46 }

  condition:
    any of them
}