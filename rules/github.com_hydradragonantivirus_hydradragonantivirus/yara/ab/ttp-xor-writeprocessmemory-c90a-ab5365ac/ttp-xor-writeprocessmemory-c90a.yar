rule TTP_XOR_WriteProcessMemory_c90a {
  strings:
    $key_c90a = { 9e 78 [2] ac 5a [2] aa 6f [2] 84 6f [2] bb 73 }

  condition:
    any of them
}