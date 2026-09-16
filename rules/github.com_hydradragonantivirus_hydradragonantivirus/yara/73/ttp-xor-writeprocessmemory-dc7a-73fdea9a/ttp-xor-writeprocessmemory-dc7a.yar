rule TTP_XOR_WriteProcessMemory_dc7a {
  strings:
    $key_dc7a = { 8b 08 [2] b9 2a [2] bf 1f [2] 91 1f [2] ae 03 }

  condition:
    any of them
}