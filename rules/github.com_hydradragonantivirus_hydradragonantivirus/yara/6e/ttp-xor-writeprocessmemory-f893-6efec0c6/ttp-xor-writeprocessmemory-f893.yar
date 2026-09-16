rule TTP_XOR_WriteProcessMemory_f893 {
  strings:
    $key_f893 = { af e1 [2] 9d c3 [2] 9b f6 [2] b5 f6 [2] 8a ea }

  condition:
    any of them
}