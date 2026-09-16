rule TTP_XOR_WriteProcessMemory_492f {
  strings:
    $key_492f = { 1e 5d [2] 2c 7f [2] 2a 4a [2] 04 4a [2] 3b 56 }

  condition:
    any of them
}