rule TTP_XOR_WriteProcessMemory_5a7a {
  strings:
    $key_5a7a = { 0d 08 [2] 3f 2a [2] 39 1f [2] 17 1f [2] 28 03 }

  condition:
    any of them
}