rule TTP_XOR_WriteProcessMemory_4c7a {
  strings:
    $key_4c7a = { 1b 08 [2] 29 2a [2] 2f 1f [2] 01 1f [2] 3e 03 }

  condition:
    any of them
}