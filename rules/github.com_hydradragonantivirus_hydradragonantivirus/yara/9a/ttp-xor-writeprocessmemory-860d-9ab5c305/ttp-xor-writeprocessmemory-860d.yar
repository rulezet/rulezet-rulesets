rule TTP_XOR_WriteProcessMemory_860d {
  strings:
    $key_860d = { d1 7f [2] e3 5d [2] e5 68 [2] cb 68 [2] f4 74 }

  condition:
    any of them
}