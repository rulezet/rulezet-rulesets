rule TTP_XOR_WriteProcessMemory_386f {
  strings:
    $key_386f = { 6f 1d [2] 5d 3f [2] 5b 0a [2] 75 0a [2] 4a 16 }

  condition:
    any of them
}