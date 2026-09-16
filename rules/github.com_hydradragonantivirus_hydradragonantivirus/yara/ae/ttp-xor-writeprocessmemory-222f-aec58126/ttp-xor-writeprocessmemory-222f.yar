rule TTP_XOR_WriteProcessMemory_222f {
  strings:
    $key_222f = { 75 5d [2] 47 7f [2] 41 4a [2] 6f 4a [2] 50 56 }

  condition:
    any of them
}