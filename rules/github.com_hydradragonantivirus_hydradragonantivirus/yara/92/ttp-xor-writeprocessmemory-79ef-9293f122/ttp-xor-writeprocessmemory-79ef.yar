rule TTP_XOR_WriteProcessMemory_79ef {
  strings:
    $key_79ef = { 2e 9d [2] 1c bf [2] 1a 8a [2] 34 8a [2] 0b 96 }

  condition:
    any of them
}