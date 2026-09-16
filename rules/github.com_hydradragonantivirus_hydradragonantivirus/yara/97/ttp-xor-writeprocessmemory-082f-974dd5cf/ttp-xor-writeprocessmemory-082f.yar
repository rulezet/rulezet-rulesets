rule TTP_XOR_WriteProcessMemory_082f {
  strings:
    $key_082f = { 5f 5d [2] 6d 7f [2] 6b 4a [2] 45 4a [2] 7a 56 }

  condition:
    any of them
}