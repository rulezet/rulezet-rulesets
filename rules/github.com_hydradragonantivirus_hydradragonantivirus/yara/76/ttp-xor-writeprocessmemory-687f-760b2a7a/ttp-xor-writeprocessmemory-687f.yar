rule TTP_XOR_WriteProcessMemory_687f {
  strings:
    $key_687f = { 3f 0d [2] 0d 2f [2] 0b 1a [2] 25 1a [2] 1a 06 }

  condition:
    any of them
}