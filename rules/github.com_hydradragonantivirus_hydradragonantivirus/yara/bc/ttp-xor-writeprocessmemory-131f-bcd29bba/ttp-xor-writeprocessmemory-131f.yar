rule TTP_XOR_WriteProcessMemory_131f {
  strings:
    $key_131f = { 44 6d [2] 76 4f [2] 70 7a [2] 5e 7a [2] 61 66 }

  condition:
    any of them
}