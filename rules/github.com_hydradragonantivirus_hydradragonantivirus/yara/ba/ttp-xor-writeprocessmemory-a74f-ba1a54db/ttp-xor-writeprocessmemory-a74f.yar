rule TTP_XOR_WriteProcessMemory_a74f {
  strings:
    $key_a74f = { f0 3d [2] c2 1f [2] c4 2a [2] ea 2a [2] d5 36 }

  condition:
    any of them
}