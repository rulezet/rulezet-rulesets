rule TTP_XOR_WriteProcessMemory_dc0a {
  strings:
    $key_dc0a = { 8b 78 [2] b9 5a [2] bf 6f [2] 91 6f [2] ae 73 }

  condition:
    any of them
}