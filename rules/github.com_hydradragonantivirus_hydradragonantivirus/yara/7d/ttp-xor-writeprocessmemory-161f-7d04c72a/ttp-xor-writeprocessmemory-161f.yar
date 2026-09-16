rule TTP_XOR_WriteProcessMemory_161f {
  strings:
    $key_161f = { 41 6d [2] 73 4f [2] 75 7a [2] 5b 7a [2] 64 66 }

  condition:
    any of them
}