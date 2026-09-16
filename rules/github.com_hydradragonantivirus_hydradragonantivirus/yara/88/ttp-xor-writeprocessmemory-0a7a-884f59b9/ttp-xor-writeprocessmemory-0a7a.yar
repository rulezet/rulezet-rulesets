rule TTP_XOR_WriteProcessMemory_0a7a {
  strings:
    $key_0a7a = { 5d 08 [2] 6f 2a [2] 69 1f [2] 47 1f [2] 78 03 }

  condition:
    any of them
}