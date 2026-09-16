rule TTP_XOR_WriteProcessMemory_bcda {
  strings:
    $key_bcda = { eb a8 [2] d9 8a [2] df bf [2] f1 bf [2] ce a3 }

  condition:
    any of them
}