rule TTP_XOR_WriteProcessMemory_bebe {
  strings:
    $key_bebe = { e9 cc [2] db ee [2] dd db [2] f3 db [2] cc c7 }

  condition:
    any of them
}