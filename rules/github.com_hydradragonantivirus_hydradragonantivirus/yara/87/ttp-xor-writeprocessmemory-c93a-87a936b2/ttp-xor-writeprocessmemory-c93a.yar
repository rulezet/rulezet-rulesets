rule TTP_XOR_WriteProcessMemory_c93a {
  strings:
    $key_c93a = { 9e 48 [2] ac 6a [2] aa 5f [2] 84 5f [2] bb 43 }

  condition:
    any of them
}