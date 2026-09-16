rule TTP_XOR_WriteProcessMemory_371f {
  strings:
    $key_371f = { 60 6d [2] 52 4f [2] 54 7a [2] 7a 7a [2] 45 66 }

  condition:
    any of them
}