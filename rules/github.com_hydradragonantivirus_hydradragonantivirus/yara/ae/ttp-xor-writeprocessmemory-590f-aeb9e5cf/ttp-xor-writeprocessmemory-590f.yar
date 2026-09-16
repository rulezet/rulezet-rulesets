rule TTP_XOR_WriteProcessMemory_590f {
  strings:
    $key_590f = { 0e 7d [2] 3c 5f [2] 3a 6a [2] 14 6a [2] 2b 76 }

  condition:
    any of them
}