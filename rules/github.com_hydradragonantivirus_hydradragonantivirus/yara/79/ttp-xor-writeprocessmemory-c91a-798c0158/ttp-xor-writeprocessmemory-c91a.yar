rule TTP_XOR_WriteProcessMemory_c91a {
  strings:
    $key_c91a = { 9e 68 [2] ac 4a [2] aa 7f [2] 84 7f [2] bb 63 }

  condition:
    any of them
}