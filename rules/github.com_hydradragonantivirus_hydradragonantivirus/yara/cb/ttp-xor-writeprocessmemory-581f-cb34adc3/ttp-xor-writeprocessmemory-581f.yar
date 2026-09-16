rule TTP_XOR_WriteProcessMemory_581f {
  strings:
    $key_581f = { 0f 6d [2] 3d 4f [2] 3b 7a [2] 15 7a [2] 2a 66 }

  condition:
    any of them
}