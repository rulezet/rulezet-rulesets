rule TTP_XOR_WriteProcessMemory_5a1a {
  strings:
    $key_5a1a = { 0d 68 [2] 3f 4a [2] 39 7f [2] 17 7f [2] 28 63 }

  condition:
    any of them
}