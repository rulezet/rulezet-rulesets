rule TTP_XOR_WriteProcessMemory_9fdf {
  strings:
    $key_9fdf = { c8 ad [2] fa 8f [2] fc ba [2] d2 ba [2] ed a6 }

  condition:
    any of them
}