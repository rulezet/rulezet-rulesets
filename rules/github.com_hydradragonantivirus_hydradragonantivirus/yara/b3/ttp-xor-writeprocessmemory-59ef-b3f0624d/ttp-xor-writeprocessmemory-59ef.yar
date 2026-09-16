rule TTP_XOR_WriteProcessMemory_59ef {
  strings:
    $key_59ef = { 0e 9d [2] 3c bf [2] 3a 8a [2] 14 8a [2] 2b 96 }

  condition:
    any of them
}