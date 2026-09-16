rule TTP_XOR_WriteProcessMemory_ee4f {
  strings:
    $key_ee4f = { b9 3d [2] 8b 1f [2] 8d 2a [2] a3 2a [2] 9c 36 }

  condition:
    any of them
}