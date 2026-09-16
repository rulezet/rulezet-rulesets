rule TTP_XOR_WriteProcessMemory_ea4f {
  strings:
    $key_ea4f = { bd 3d [2] 8f 1f [2] 89 2a [2] a7 2a [2] 98 36 }

  condition:
    any of them
}