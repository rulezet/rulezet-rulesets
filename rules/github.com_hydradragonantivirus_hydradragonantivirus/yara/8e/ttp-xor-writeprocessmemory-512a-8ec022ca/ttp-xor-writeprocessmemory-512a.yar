rule TTP_XOR_WriteProcessMemory_512a {
  strings:
    $key_512a = { 06 58 [2] 34 7a [2] 32 4f [2] 1c 4f [2] 23 53 }

  condition:
    any of them
}