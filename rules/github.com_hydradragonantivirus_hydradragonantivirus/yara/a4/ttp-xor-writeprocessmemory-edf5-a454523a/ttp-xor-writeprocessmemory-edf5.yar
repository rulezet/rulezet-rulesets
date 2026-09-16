rule TTP_XOR_WriteProcessMemory_edf5 {
  strings:
    $key_edf5 = { ba 87 [2] 88 a5 [2] 8e 90 [2] a0 90 [2] 9f 8c }

  condition:
    any of them
}