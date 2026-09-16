rule TTP_XOR_WriteProcessMemory_2b4f {
  strings:
    $key_2b4f = { 7c 3d [2] 4e 1f [2] 48 2a [2] 66 2a [2] 59 36 }

  condition:
    any of them
}