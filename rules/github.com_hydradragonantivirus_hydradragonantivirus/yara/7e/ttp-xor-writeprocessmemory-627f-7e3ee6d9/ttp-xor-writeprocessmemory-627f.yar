rule TTP_XOR_WriteProcessMemory_627f {
  strings:
    $key_627f = { 35 0d [2] 07 2f [2] 01 1a [2] 2f 1a [2] 10 06 }

  condition:
    any of them
}