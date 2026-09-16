rule TTP_XOR_WriteProcessMemory_69ef {
  strings:
    $key_69ef = { 3e 9d [2] 0c bf [2] 0a 8a [2] 24 8a [2] 1b 96 }

  condition:
    any of them
}