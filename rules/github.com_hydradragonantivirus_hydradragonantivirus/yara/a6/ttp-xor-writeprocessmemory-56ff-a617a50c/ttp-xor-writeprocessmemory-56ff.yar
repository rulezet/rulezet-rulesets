rule TTP_XOR_WriteProcessMemory_56ff {
  strings:
    $key_56ff = { 01 8d [2] 33 af [2] 35 9a [2] 1b 9a [2] 24 86 }

  condition:
    any of them
}