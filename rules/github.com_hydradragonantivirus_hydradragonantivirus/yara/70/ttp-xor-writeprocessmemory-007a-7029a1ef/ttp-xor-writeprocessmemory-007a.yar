rule TTP_XOR_WriteProcessMemory_007a {
  strings:
    $key_007a = { 57 08 [2] 65 2a [2] 63 1f [2] 4d 1f [2] 72 03 }

  condition:
    any of them
}