rule TTP_XOR_WriteProcessMemory_f91f {
  strings:
    $key_f91f = { ae 6d [2] 9c 4f [2] 9a 7a [2] b4 7a [2] 8b 66 }

  condition:
    any of them
}