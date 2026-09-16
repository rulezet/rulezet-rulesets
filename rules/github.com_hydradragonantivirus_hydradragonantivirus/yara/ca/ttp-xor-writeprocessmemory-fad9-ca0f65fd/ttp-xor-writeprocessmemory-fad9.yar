rule TTP_XOR_WriteProcessMemory_fad9 {
  strings:
    $key_fad9 = { ad ab [2] 9f 89 [2] 99 bc [2] b7 bc [2] 88 a0 }

  condition:
    any of them
}