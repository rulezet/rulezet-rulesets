rule TTP_XOR_WriteProcessMemory_e34f {
  strings:
    $key_e34f = { b4 3d [2] 86 1f [2] 80 2a [2] ae 2a [2] 91 36 }

  condition:
    any of them
}