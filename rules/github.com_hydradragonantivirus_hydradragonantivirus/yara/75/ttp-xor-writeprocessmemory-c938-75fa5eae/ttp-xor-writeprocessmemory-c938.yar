rule TTP_XOR_WriteProcessMemory_c938 {
  strings:
    $key_c938 = { 9e 4a [2] ac 68 [2] aa 5d [2] 84 5d [2] bb 41 }

  condition:
    any of them
}