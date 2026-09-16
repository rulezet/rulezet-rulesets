rule TTP_XOR_WriteProcessMemory_775a {
  strings:
    $key_775a = { 20 28 [2] 12 0a [2] 14 3f [2] 3a 3f [2] 05 23 }

  condition:
    any of them
}