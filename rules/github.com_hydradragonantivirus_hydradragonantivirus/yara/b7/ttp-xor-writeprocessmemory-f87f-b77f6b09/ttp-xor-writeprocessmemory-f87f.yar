rule TTP_XOR_WriteProcessMemory_f87f {
  strings:
    $key_f87f = { af 0d [2] 9d 2f [2] 9b 1a [2] b5 1a [2] 8a 06 }

  condition:
    any of them
}