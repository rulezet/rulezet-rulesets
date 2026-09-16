rule TTP_XOR_WriteProcessMemory_9fce {
  strings:
    $key_9fce = { c8 bc [2] fa 9e [2] fc ab [2] d2 ab [2] ed b7 }

  condition:
    any of them
}