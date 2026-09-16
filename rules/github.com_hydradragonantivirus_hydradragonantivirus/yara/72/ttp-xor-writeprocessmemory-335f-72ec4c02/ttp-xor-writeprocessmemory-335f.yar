rule TTP_XOR_WriteProcessMemory_335f {
  strings:
    $key_335f = { 64 2d [2] 56 0f [2] 50 3a [2] 7e 3a [2] 41 26 }

  condition:
    any of them
}