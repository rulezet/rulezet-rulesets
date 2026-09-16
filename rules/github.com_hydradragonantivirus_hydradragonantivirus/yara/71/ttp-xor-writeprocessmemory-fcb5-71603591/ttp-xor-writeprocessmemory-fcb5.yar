rule TTP_XOR_WriteProcessMemory_fcb5 {
  strings:
    $key_fcb5 = { ab c7 [2] 99 e5 [2] 9f d0 [2] b1 d0 [2] 8e cc }

  condition:
    any of them
}