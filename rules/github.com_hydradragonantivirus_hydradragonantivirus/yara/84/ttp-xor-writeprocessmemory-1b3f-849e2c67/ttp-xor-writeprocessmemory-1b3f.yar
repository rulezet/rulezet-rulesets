rule TTP_XOR_WriteProcessMemory_1b3f {
  strings:
    $key_1b3f = { 4c 4d [2] 7e 6f [2] 78 5a [2] 56 5a [2] 69 46 }

  condition:
    any of them
}