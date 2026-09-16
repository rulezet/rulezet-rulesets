rule TTP_XOR_WriteProcessMemory_becd {
  strings:
    $key_becd = { e9 bf [2] db 9d [2] dd a8 [2] f3 a8 [2] cc b4 }

  condition:
    any of them
}