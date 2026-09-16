rule TTP_XOR_WriteProcessMemory_680a {
  strings:
    $key_680a = { 3f 78 [2] 0d 5a [2] 0b 6f [2] 25 6f [2] 1a 73 }

  condition:
    any of them
}