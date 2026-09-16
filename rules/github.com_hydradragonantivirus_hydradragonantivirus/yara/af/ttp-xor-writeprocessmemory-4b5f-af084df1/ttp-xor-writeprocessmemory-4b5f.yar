rule TTP_XOR_WriteProcessMemory_4b5f {
  strings:
    $key_4b5f = { 1c 2d [2] 2e 0f [2] 28 3a [2] 06 3a [2] 39 26 }

  condition:
    any of them
}