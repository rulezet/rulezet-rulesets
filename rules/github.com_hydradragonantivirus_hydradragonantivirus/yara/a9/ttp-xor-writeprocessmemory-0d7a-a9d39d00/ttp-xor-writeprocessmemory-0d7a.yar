rule TTP_XOR_WriteProcessMemory_0d7a {
  strings:
    $key_0d7a = { 5a 08 [2] 68 2a [2] 6e 1f [2] 40 1f [2] 7f 03 }

  condition:
    any of them
}