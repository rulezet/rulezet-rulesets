rule TTP_XOR_WriteProcessMemory_005a {
  strings:
    $key_005a = { 57 28 [2] 65 0a [2] 63 3f [2] 4d 3f [2] 72 23 }

  condition:
    any of them
}