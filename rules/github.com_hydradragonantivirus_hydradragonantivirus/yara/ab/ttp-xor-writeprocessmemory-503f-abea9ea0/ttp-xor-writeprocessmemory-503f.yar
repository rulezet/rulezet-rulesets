rule TTP_XOR_WriteProcessMemory_503f {
  strings:
    $key_503f = { 07 4d [2] 35 6f [2] 33 5a [2] 1d 5a [2] 22 46 }

  condition:
    any of them
}