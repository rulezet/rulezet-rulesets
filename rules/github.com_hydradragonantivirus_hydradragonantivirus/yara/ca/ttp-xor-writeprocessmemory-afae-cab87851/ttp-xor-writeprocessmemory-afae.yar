rule TTP_XOR_WriteProcessMemory_afae {
  strings:
    $key_afae = { f8 dc [2] ca fe [2] cc cb [2] e2 cb [2] dd d7 }

  condition:
    any of them
}