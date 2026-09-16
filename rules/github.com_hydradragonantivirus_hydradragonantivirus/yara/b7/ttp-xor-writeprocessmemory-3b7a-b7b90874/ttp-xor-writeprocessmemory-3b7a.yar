rule TTP_XOR_WriteProcessMemory_3b7a {
  strings:
    $key_3b7a = { 6c 08 [2] 5e 2a [2] 58 1f [2] 76 1f [2] 49 03 }

  condition:
    any of them
}