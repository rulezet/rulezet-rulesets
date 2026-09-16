rule TTP_XOR_WriteProcessMemory_ed88 {
  strings:
    $key_ed88 = { ba fa [2] 88 d8 [2] 8e ed [2] a0 ed [2] 9f f1 }

  condition:
    any of them
}