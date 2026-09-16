rule TTP_XOR_WriteProcessMemory_bc4f {
  strings:
    $key_bc4f = { eb 3d [2] d9 1f [2] df 2a [2] f1 2a [2] ce 36 }

  condition:
    any of them
}