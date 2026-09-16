rule TTP_XOR_WriteProcessMemory_284f {
  strings:
    $key_284f = { 7f 3d [2] 4d 1f [2] 4b 2a [2] 65 2a [2] 5a 36 }

  condition:
    any of them
}