rule TTP_XOR_WriteProcessMemory_582f {
  strings:
    $key_582f = { 0f 5d [2] 3d 7f [2] 3b 4a [2] 15 4a [2] 2a 56 }

  condition:
    any of them
}