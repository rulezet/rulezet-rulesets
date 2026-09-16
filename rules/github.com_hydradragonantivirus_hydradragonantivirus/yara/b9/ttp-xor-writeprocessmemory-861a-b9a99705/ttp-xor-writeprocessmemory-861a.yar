rule TTP_XOR_WriteProcessMemory_861a {
  strings:
    $key_861a = { d1 68 [2] e3 4a [2] e5 7f [2] cb 7f [2] f4 63 }

  condition:
    any of them
}