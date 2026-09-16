rule TTP_XOR_WriteProcessMemory_864f {
  strings:
    $key_864f = { d1 3d [2] e3 1f [2] e5 2a [2] cb 2a [2] f4 36 }

  condition:
    any of them
}