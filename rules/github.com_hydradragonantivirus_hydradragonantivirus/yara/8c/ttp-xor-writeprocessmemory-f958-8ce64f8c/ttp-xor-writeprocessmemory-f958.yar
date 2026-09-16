rule TTP_XOR_WriteProcessMemory_f958 {
  strings:
    $key_f958 = { ae 2a [2] 9c 08 [2] 9a 3d [2] b4 3d [2] 8b 21 }

  condition:
    any of them
}