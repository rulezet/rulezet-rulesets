rule TTP_XOR_WriteProcessMemory_314f {
  strings:
    $key_314f = { 66 3d [2] 54 1f [2] 52 2a [2] 7c 2a [2] 43 36 }

  condition:
    any of them
}