rule TTP_XOR_WriteProcessMemory_dd88 {
  strings:
    $key_dd88 = { 8a fa [2] b8 d8 [2] be ed [2] 90 ed [2] af f1 }

  condition:
    any of them
}