rule TTP_XOR_WriteProcessMemory_245f {
  strings:
    $key_245f = { 73 2d [2] 41 0f [2] 47 3a [2] 69 3a [2] 56 26 }

  condition:
    any of them
}