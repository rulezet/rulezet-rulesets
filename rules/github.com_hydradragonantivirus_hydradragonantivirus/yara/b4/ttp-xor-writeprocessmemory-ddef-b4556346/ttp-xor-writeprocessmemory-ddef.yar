rule TTP_XOR_WriteProcessMemory_ddef {
  strings:
    $key_ddef = { 8a 9d [2] b8 bf [2] be 8a [2] 90 8a [2] af 96 }

  condition:
    any of them
}