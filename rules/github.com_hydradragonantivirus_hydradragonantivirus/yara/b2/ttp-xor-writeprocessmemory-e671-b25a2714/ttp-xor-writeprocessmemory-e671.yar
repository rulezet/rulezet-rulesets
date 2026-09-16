rule TTP_XOR_WriteProcessMemory_e671 {
  strings:
    $key_e671 = { b1 03 [2] 83 21 [2] 85 14 [2] ab 14 [2] 94 08 }

  condition:
    any of them
}