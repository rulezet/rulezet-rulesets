rule TTP_XOR_WriteProcessMemory_e688 {
  strings:
    $key_e688 = { b1 fa [2] 83 d8 [2] 85 ed [2] ab ed [2] 94 f1 }

  condition:
    any of them
}