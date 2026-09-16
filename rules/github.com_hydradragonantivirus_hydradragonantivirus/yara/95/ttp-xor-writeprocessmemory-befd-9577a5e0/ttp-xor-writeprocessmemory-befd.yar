rule TTP_XOR_WriteProcessMemory_befd {
  strings:
    $key_befd = { e9 8f [2] db ad [2] dd 98 [2] f3 98 [2] cc 84 }

  condition:
    any of them
}