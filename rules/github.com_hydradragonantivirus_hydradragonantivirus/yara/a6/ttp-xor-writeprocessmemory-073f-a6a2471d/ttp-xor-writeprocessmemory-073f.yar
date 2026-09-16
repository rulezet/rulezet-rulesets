rule TTP_XOR_WriteProcessMemory_073f {
  strings:
    $key_073f = { 50 4d [2] 62 6f [2] 64 5a [2] 4a 5a [2] 75 46 }

  condition:
    any of them
}