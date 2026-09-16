rule TTP_XOR_WriteProcessMemory_331f {
  strings:
    $key_331f = { 64 6d [2] 56 4f [2] 50 7a [2] 7e 7a [2] 41 66 }

  condition:
    any of them
}