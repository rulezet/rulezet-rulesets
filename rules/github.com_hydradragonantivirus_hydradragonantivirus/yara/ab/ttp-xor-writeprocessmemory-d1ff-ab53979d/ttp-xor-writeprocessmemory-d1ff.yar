rule TTP_XOR_WriteProcessMemory_d1ff {
  strings:
    $key_d1ff = { 86 8d [2] b4 af [2] b2 9a [2] 9c 9a [2] a3 86 }

  condition:
    any of them
}