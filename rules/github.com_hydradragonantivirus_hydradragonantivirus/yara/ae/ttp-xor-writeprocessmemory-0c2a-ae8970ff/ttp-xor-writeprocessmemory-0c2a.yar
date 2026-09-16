rule TTP_XOR_WriteProcessMemory_0c2a {
  strings:
    $key_0c2a = { 5b 58 [2] 69 7a [2] 6f 4f [2] 41 4f [2] 7e 53 }

  condition:
    any of them
}