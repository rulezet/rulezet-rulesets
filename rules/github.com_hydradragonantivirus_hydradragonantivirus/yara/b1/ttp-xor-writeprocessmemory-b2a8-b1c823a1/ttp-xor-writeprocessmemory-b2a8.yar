rule TTP_XOR_WriteProcessMemory_b2a8 {
  strings:
    $key_b2a8 = { e5 da [2] d7 f8 [2] d1 cd [2] ff cd [2] c0 d1 }

  condition:
    any of them
}