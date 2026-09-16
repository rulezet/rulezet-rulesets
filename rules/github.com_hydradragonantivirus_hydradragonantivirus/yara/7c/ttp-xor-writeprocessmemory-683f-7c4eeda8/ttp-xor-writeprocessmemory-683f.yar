rule TTP_XOR_WriteProcessMemory_683f {
  strings:
    $key_683f = { 3f 4d [2] 0d 6f [2] 0b 5a [2] 25 5a [2] 1a 46 }

  condition:
    any of them
}