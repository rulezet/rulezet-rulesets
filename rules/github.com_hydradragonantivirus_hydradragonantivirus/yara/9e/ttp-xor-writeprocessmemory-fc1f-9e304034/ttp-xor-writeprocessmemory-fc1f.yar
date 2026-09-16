rule TTP_XOR_WriteProcessMemory_fc1f {
  strings:
    $key_fc1f = { ab 6d [2] 99 4f [2] 9f 7a [2] b1 7a [2] 8e 66 }

  condition:
    any of them
}