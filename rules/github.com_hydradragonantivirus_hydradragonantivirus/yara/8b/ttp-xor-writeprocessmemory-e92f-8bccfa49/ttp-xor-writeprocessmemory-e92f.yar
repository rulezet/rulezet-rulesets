rule TTP_XOR_WriteProcessMemory_e92f {
  strings:
    $key_e92f = { be 5d [2] 8c 7f [2] 8a 4a [2] a4 4a [2] 9b 56 }

  condition:
    any of them
}