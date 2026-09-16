rule TTP_XOR_WriteProcessMemory_2a2a {
  strings:
    $key_2a2a = { 7d 58 [2] 4f 7a [2] 49 4f [2] 67 4f [2] 58 53 }

  condition:
    any of them
}