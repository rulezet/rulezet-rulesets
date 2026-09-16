rule TTP_XOR_WriteProcessMemory_425a {
  strings:
    $key_425a = { 15 28 [2] 27 0a [2] 21 3f [2] 0f 3f [2] 30 23 }

  condition:
    any of them
}