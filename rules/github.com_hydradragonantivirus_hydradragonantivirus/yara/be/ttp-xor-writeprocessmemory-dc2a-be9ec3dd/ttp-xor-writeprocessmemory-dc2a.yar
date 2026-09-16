rule TTP_XOR_WriteProcessMemory_dc2a {
  strings:
    $key_dc2a = { 8b 58 [2] b9 7a [2] bf 4f [2] 91 4f [2] ae 53 }

  condition:
    any of them
}