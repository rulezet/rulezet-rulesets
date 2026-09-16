rule TTP_XOR_WriteProcessMemory_0c7a {
  strings:
    $key_0c7a = { 5b 08 [2] 69 2a [2] 6f 1f [2] 41 1f [2] 7e 03 }

  condition:
    any of them
}