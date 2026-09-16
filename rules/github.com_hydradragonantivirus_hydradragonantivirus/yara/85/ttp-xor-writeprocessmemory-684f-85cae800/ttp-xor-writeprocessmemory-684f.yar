rule TTP_XOR_WriteProcessMemory_684f {
  strings:
    $key_684f = { 3f 3d [2] 0d 1f [2] 0b 2a [2] 25 2a [2] 1a 36 }

  condition:
    any of them
}