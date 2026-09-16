rule TTP_XOR_WriteProcessMemory_795f {
  strings:
    $key_795f = { 2e 2d [2] 1c 0f [2] 1a 3a [2] 34 3a [2] 0b 26 }

  condition:
    any of them
}