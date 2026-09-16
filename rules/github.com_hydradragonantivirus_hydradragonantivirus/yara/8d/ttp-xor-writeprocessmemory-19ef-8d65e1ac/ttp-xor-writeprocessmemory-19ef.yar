rule TTP_XOR_WriteProcessMemory_19ef {
  strings:
    $key_19ef = { 4e 9d [2] 7c bf [2] 7a 8a [2] 54 8a [2] 6b 96 }

  condition:
    any of them
}