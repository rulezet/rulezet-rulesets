rule TTP_XOR_WriteProcessMemory_c97a {
  strings:
    $key_c97a = { 9e 08 [2] ac 2a [2] aa 1f [2] 84 1f [2] bb 03 }

  condition:
    any of them
}