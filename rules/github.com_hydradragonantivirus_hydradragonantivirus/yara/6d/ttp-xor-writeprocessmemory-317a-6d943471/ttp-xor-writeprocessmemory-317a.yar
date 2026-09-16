rule TTP_XOR_WriteProcessMemory_317a {
  strings:
    $key_317a = { 66 08 [2] 54 2a [2] 52 1f [2] 7c 1f [2] 43 03 }

  condition:
    any of them
}