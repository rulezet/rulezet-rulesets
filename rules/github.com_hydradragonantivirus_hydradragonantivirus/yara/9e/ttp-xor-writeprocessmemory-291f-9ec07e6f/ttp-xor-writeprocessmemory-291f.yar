rule TTP_XOR_WriteProcessMemory_291f {
  strings:
    $key_291f = { 7e 6d [2] 4c 4f [2] 4a 7a [2] 64 7a [2] 5b 66 }

  condition:
    any of them
}