rule TTP_XOR_WriteProcessMemory_694f {
  strings:
    $key_694f = { 3e 3d [2] 0c 1f [2] 0a 2a [2] 24 2a [2] 1b 36 }

  condition:
    any of them
}