rule TTP_XOR_WriteProcessMemory_242a {
  strings:
    $key_242a = { 73 58 [2] 41 7a [2] 47 4f [2] 69 4f [2] 56 53 }

  condition:
    any of them
}