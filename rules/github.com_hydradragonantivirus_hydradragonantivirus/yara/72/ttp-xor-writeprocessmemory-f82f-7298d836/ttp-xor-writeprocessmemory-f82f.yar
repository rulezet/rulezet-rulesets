rule TTP_XOR_WriteProcessMemory_f82f {
  strings:
    $key_f82f = { af 5d [2] 9d 7f [2] 9b 4a [2] b5 4a [2] 8a 56 }

  condition:
    any of them
}