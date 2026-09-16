rule TTP_XOR_WriteProcessMemory_1b0f {
  strings:
    $key_1b0f = { 4c 7d [2] 7e 5f [2] 78 6a [2] 56 6a [2] 69 76 }

  condition:
    any of them
}