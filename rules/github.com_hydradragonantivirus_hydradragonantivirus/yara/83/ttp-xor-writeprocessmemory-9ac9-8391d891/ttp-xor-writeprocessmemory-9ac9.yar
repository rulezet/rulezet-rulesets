rule TTP_XOR_WriteProcessMemory_9ac9 {
  strings:
    $key_9ac9 = { cd bb [2] ff 99 [2] f9 ac [2] d7 ac [2] e8 b0 }

  condition:
    any of them
}