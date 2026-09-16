rule TTP_XOR_WriteProcessMemory_f92f {
  strings:
    $key_f92f = { ae 5d [2] 9c 7f [2] 9a 4a [2] b4 4a [2] 8b 56 }

  condition:
    any of them
}