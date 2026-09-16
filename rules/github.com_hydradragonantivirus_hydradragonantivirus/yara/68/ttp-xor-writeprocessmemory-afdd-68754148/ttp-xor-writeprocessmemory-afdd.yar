rule TTP_XOR_WriteProcessMemory_afdd {
  strings:
    $key_afdd = { f8 af [2] ca 8d [2] cc b8 [2] e2 b8 [2] dd a4 }

  condition:
    any of them
}