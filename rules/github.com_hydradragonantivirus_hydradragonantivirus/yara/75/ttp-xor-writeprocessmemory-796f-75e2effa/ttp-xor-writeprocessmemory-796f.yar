rule TTP_XOR_WriteProcessMemory_796f {
  strings:
    $key_796f = { 2e 1d [2] 1c 3f [2] 1a 0a [2] 34 0a [2] 0b 16 }

  condition:
    any of them
}