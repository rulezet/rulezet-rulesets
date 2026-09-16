rule TTP_XOR_WriteProcessMemory_9aef {
  strings:
    $key_9aef = { cd 9d [2] ff bf [2] f9 8a [2] d7 8a [2] e8 96 }

  condition:
    any of them
}