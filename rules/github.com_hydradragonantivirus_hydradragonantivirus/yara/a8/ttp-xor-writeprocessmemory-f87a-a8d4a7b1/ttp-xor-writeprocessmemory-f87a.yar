rule TTP_XOR_WriteProcessMemory_f87a {
  strings:
    $key_f87a = { af 08 [2] 9d 2a [2] 9b 1f [2] b5 1f [2] 8a 03 }

  condition:
    any of them
}