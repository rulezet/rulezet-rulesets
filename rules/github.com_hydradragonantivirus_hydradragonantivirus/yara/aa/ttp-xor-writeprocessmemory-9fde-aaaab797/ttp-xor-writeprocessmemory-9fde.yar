rule TTP_XOR_WriteProcessMemory_9fde {
  strings:
    $key_9fde = { c8 ac [2] fa 8e [2] fc bb [2] d2 bb [2] ed a7 }

  condition:
    any of them
}