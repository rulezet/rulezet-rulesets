rule TTP_XOR_WriteProcessMemory_adef {
  strings:
    $key_adef = { fa 9d [2] c8 bf [2] ce 8a [2] e0 8a [2] df 96 }

  condition:
    any of them
}