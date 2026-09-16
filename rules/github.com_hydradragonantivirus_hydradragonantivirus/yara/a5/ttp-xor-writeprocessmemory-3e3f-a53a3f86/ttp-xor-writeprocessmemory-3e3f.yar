rule TTP_XOR_WriteProcessMemory_3e3f {
  strings:
    $key_3e3f = { 69 4d [2] 5b 6f [2] 5d 5a [2] 73 5a [2] 4c 46 }

  condition:
    any of them
}