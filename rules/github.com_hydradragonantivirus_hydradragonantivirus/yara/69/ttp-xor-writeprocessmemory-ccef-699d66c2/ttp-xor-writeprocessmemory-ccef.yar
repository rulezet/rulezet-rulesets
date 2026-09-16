rule TTP_XOR_WriteProcessMemory_ccef {
  strings:
    $key_ccef = { 9b 9d [2] a9 bf [2] af 8a [2] 81 8a [2] be 96 }

  condition:
    any of them
}