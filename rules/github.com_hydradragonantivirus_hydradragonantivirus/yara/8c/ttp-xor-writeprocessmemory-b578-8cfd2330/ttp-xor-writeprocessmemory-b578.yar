rule TTP_XOR_WriteProcessMemory_b578 {
  strings:
    $key_b578 = { e2 0a [2] d0 28 [2] d6 1d [2] f8 1d [2] c7 01 }

  condition:
    any of them
}