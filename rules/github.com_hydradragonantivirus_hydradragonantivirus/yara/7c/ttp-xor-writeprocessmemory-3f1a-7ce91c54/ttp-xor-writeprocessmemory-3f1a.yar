rule TTP_XOR_WriteProcessMemory_3f1a {
  strings:
    $key_3f1a = { 68 68 [2] 5a 4a [2] 5c 7f [2] 72 7f [2] 4d 63 }

  condition:
    any of them
}