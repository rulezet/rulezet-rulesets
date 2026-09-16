rule TTP_XOR_WriteProcessMemory_abda {
  strings:
    $key_abda = { fc a8 [2] ce 8a [2] c8 bf [2] e6 bf [2] d9 a3 }

  condition:
    any of them
}