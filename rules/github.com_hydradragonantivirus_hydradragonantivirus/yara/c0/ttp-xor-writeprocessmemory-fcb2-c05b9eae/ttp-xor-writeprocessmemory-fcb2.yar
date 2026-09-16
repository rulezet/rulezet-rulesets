rule TTP_XOR_WriteProcessMemory_fcb2 {
  strings:
    $key_fcb2 = { ab c0 [2] 99 e2 [2] 9f d7 [2] b1 d7 [2] 8e cb }

  condition:
    any of them
}