rule TTP_XOR_WriteProcessMemory_dc3a {
  strings:
    $key_dc3a = { 8b 48 [2] b9 6a [2] bf 5f [2] 91 5f [2] ae 43 }

  condition:
    any of them
}