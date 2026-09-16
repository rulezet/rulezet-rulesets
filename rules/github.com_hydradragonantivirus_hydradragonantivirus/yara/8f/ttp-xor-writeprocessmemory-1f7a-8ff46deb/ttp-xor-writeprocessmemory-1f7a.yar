rule TTP_XOR_WriteProcessMemory_1f7a {
  strings:
    $key_1f7a = { 48 08 [2] 7a 2a [2] 7c 1f [2] 52 1f [2] 6d 03 }

  condition:
    any of them
}