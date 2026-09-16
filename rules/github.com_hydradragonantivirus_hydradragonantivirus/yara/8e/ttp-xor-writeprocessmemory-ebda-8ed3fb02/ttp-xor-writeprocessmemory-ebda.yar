rule TTP_XOR_WriteProcessMemory_ebda {
  strings:
    $key_ebda = { bc a8 [2] 8e 8a [2] 88 bf [2] a6 bf [2] 99 a3 }

  condition:
    any of them
}