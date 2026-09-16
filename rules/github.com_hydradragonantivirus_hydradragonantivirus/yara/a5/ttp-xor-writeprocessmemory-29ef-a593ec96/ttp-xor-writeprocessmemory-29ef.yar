rule TTP_XOR_WriteProcessMemory_29ef {
  strings:
    $key_29ef = { 7e 9d [2] 4c bf [2] 4a 8a [2] 64 8a [2] 5b 96 }

  condition:
    any of them
}