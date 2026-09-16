rule TTP_XOR_WriteProcessMemory_0e3f {
  strings:
    $key_0e3f = { 59 4d [2] 6b 6f [2] 6d 5a [2] 43 5a [2] 7c 46 }

  condition:
    any of them
}