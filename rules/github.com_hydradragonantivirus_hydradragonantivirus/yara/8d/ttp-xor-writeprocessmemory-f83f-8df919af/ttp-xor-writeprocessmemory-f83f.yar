rule TTP_XOR_WriteProcessMemory_f83f {
  strings:
    $key_f83f = { af 4d [2] 9d 6f [2] 9b 5a [2] b5 5a [2] 8a 46 }

  condition:
    any of them
}