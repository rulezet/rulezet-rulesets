rule TTP_XOR_WriteProcessMemory_6f7a {
  strings:
    $key_6f7a = { 38 08 [2] 0a 2a [2] 0c 1f [2] 22 1f [2] 1d 03 }

  condition:
    any of them
}