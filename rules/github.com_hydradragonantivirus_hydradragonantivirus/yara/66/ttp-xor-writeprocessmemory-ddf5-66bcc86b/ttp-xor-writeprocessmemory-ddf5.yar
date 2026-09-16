rule TTP_XOR_WriteProcessMemory_ddf5 {
  strings:
    $key_ddf5 = { 8a 87 [2] b8 a5 [2] be 90 [2] 90 90 [2] af 8c }

  condition:
    any of them
}