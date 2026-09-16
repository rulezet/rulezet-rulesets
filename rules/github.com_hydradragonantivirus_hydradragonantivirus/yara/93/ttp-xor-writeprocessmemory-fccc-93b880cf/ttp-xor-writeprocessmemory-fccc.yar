rule TTP_XOR_WriteProcessMemory_fccc {
  strings:
    $key_fccc = { ab be [2] 99 9c [2] 9f a9 [2] b1 a9 [2] 8e b5 }

  condition:
    any of them
}