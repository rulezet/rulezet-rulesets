rule TTP_XOR_WriteProcessMemory_752a {
  strings:
    $key_752a = { 22 58 [2] 10 7a [2] 16 4f [2] 38 4f [2] 07 53 }

  condition:
    any of them
}