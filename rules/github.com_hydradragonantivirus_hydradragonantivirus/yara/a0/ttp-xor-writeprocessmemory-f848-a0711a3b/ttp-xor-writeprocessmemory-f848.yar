rule TTP_XOR_WriteProcessMemory_f848 {
  strings:
    $key_f848 = { af 3a [2] 9d 18 [2] 9b 2d [2] b5 2d [2] 8a 31 }

  condition:
    any of them
}