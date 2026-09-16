rule TTP_XOR_WriteProcessMemory_243f {
  strings:
    $key_243f = { 73 4d [2] 41 6f [2] 47 5a [2] 69 5a [2] 56 46 }

  condition:
    any of them
}