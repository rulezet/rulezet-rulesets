rule TTP_XOR_WriteProcessMemory_eea5 {
  strings:
    $key_eea5 = { b9 d7 [2] 8b f5 [2] 8d c0 [2] a3 c0 [2] 9c dc }

  condition:
    any of them
}