rule TTP_XOR_WriteProcessMemory_215f {
  strings:
    $key_215f = { 76 2d [2] 44 0f [2] 42 3a [2] 6c 3a [2] 53 26 }

  condition:
    any of them
}