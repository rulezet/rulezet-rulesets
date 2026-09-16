rule TTP_XOR_WriteProcessMemory_adda {
  strings:
    $key_adda = { fa a8 [2] c8 8a [2] ce bf [2] e0 bf [2] df a3 }

  condition:
    any of them
}