rule TTP_XOR_WriteProcessMemory_353f {
  strings:
    $key_353f = { 62 4d [2] 50 6f [2] 56 5a [2] 78 5a [2] 47 46 }

  condition:
    any of them
}