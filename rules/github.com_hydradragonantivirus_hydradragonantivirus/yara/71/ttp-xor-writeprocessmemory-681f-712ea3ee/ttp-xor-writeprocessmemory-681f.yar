rule TTP_XOR_WriteProcessMemory_681f {
  strings:
    $key_681f = { 3f 6d [2] 0d 4f [2] 0b 7a [2] 25 7a [2] 1a 66 }

  condition:
    any of them
}