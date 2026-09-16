rule TTP_XOR_WriteProcessMemory_0e2a {
  strings:
    $key_0e2a = { 59 58 [2] 6b 7a [2] 6d 4f [2] 43 4f [2] 7c 53 }

  condition:
    any of them
}