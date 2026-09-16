rule TTP_XOR_WriteProcessMemory_471f {
  strings:
    $key_471f = { 10 6d [2] 22 4f [2] 24 7a [2] 0a 7a [2] 35 66 }

  condition:
    any of them
}