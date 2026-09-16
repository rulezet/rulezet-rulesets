rule TTP_XOR_WriteProcessMemory_012a {
  strings:
    $key_012a = { 56 58 [2] 64 7a [2] 62 4f [2] 4c 4f [2] 73 53 }

  condition:
    any of them
}