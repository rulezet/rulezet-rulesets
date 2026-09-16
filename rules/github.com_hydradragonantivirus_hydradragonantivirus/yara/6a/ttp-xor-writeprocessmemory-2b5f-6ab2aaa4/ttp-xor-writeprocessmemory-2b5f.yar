rule TTP_XOR_WriteProcessMemory_2b5f {
  strings:
    $key_2b5f = { 7c 2d [2] 4e 0f [2] 48 3a [2] 66 3a [2] 59 26 }

  condition:
    any of them
}