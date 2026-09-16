rule TTP_XOR_WriteProcessMemory_163f {
  strings:
    $key_163f = { 41 4d [2] 73 6f [2] 75 5a [2] 5b 5a [2] 64 46 }

  condition:
    any of them
}