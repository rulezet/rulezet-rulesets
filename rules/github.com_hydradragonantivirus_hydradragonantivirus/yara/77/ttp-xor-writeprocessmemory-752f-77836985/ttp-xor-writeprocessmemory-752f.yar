rule TTP_XOR_WriteProcessMemory_752f {
  strings:
    $key_752f = { 22 5d [2] 10 7f [2] 16 4a [2] 38 4a [2] 07 56 }

  condition:
    any of them
}