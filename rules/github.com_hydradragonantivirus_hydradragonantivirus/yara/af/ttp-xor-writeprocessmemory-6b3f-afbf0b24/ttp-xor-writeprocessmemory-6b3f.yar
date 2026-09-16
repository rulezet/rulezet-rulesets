rule TTP_XOR_WriteProcessMemory_6b3f {
  strings:
    $key_6b3f = { 3c 4d [2] 0e 6f [2] 08 5a [2] 26 5a [2] 19 46 }

  condition:
    any of them
}