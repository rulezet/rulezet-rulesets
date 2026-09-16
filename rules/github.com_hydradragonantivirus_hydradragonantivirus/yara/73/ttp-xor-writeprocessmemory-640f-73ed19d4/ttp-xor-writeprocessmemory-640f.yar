rule TTP_XOR_WriteProcessMemory_640f {
  strings:
    $key_640f = { 33 7d [2] 01 5f [2] 07 6a [2] 29 6a [2] 16 76 }

  condition:
    any of them
}