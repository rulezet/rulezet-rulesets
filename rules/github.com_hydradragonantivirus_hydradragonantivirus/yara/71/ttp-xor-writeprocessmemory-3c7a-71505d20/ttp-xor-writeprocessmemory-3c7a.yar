rule TTP_XOR_WriteProcessMemory_3c7a {
  strings:
    $key_3c7a = { 6b 08 [2] 59 2a [2] 5f 1f [2] 71 1f [2] 4e 03 }

  condition:
    any of them
}