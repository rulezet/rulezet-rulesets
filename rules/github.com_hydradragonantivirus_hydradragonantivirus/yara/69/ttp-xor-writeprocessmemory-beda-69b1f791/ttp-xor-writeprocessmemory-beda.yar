rule TTP_XOR_WriteProcessMemory_beda {
  strings:
    $key_beda = { e9 a8 [2] db 8a [2] dd bf [2] f3 bf [2] cc a3 }

  condition:
    any of them
}