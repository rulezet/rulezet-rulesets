rule TTP_XOR_WriteProcessMemory_8dc9 {
  strings:
    $key_8dc9 = { da bb [2] e8 99 [2] ee ac [2] c0 ac [2] ff b0 }

  condition:
    any of them
}