rule TTP_XOR_WriteProcessMemory_4b2f {
  strings:
    $key_4b2f = { 1c 5d [2] 2e 7f [2] 28 4a [2] 06 4a [2] 39 56 }

  condition:
    any of them
}