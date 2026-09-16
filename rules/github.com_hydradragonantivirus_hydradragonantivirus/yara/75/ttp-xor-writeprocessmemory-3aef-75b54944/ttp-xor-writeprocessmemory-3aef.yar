rule TTP_XOR_WriteProcessMemory_3aef {
  strings:
    $key_3aef = { 6d 9d [2] 5f bf [2] 59 8a [2] 77 8a [2] 48 96 }

  condition:
    any of them
}