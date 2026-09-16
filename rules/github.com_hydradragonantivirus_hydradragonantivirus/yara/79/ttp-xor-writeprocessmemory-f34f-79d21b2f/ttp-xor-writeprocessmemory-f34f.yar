rule TTP_XOR_WriteProcessMemory_f34f {
  strings:
    $key_f34f = { a4 3d [2] 96 1f [2] 90 2a [2] be 2a [2] 81 36 }

  condition:
    any of them
}