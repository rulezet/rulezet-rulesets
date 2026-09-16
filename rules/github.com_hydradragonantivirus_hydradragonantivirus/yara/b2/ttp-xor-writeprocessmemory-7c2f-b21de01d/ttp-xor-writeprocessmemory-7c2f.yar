rule TTP_XOR_WriteProcessMemory_7c2f {
  strings:
    $key_7c2f = { 2b 5d [2] 19 7f [2] 1f 4a [2] 31 4a [2] 0e 56 }

  condition:
    any of them
}