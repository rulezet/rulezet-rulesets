rule TTP_XOR_WriteProcessMemory_b709 {
  strings:
    $key_b709 = { e0 7b [2] d2 59 [2] d4 6c [2] fa 6c [2] c5 70 }

  condition:
    any of them
}