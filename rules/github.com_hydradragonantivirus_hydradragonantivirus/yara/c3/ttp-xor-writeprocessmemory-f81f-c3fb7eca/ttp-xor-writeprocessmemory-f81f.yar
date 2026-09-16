rule TTP_XOR_WriteProcessMemory_f81f {
  strings:
    $key_f81f = { af 6d [2] 9d 4f [2] 9b 7a [2] b5 7a [2] 8a 66 }

  condition:
    any of them
}