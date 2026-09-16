rule TTP_XOR_WriteProcessMemory_f96f {
  strings:
    $key_f96f = { ae 1d [2] 9c 3f [2] 9a 0a [2] b4 0a [2] 8b 16 }

  condition:
    any of them
}