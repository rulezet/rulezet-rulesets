rule TTP_XOR_WriteProcessMemory_794f {
  strings:
    $key_794f = { 2e 3d [2] 1c 1f [2] 1a 2a [2] 34 2a [2] 0b 36 }

  condition:
    any of them
}