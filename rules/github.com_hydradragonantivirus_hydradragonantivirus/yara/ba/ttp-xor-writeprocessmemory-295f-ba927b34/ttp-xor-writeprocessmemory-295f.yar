rule TTP_XOR_WriteProcessMemory_295f {
  strings:
    $key_295f = { 7e 2d [2] 4c 0f [2] 4a 3a [2] 64 3a [2] 5b 26 }

  condition:
    any of them
}