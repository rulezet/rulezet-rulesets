rule TTP_XOR_WriteProcessMemory_bac9 {
  strings:
    $key_bac9 = { ed bb [2] df 99 [2] d9 ac [2] f7 ac [2] c8 b0 }

  condition:
    any of them
}