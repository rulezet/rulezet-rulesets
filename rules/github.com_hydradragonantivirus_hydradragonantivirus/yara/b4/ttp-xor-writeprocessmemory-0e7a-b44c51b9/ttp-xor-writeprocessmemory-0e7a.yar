rule TTP_XOR_WriteProcessMemory_0e7a {
  strings:
    $key_0e7a = { 59 08 [2] 6b 2a [2] 6d 1f [2] 43 1f [2] 7c 03 }

  condition:
    any of them
}