rule TTP_XOR_WriteProcessMemory_fea5 {
  strings:
    $key_fea5 = { a9 d7 [2] 9b f5 [2] 9d c0 [2] b3 c0 [2] 8c dc }

  condition:
    any of them
}