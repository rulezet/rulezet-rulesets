rule TTP_XOR_WriteProcessMemory_1f3f {
  strings:
    $key_1f3f = { 48 4d [2] 7a 6f [2] 7c 5a [2] 52 5a [2] 6d 46 }

  condition:
    any of them
}