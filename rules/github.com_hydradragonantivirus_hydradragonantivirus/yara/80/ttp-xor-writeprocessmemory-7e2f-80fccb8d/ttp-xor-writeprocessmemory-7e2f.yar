rule TTP_XOR_WriteProcessMemory_7e2f {
  strings:
    $key_7e2f = { 29 5d [2] 1b 7f [2] 1d 4a [2] 33 4a [2] 0c 56 }

  condition:
    any of them
}