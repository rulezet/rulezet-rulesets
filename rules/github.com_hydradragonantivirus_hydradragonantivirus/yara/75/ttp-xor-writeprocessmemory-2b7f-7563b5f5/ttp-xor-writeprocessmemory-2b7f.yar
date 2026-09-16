rule TTP_XOR_WriteProcessMemory_2b7f {
  strings:
    $key_2b7f = { 7c 0d [2] 4e 2f [2] 48 1a [2] 66 1a [2] 59 06 }

  condition:
    any of them
}