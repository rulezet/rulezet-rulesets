rule TTP_XOR_WriteProcessMemory_0698 {
  strings:
    $key_0698 = { 51 ea [2] 63 c8 [2] 65 fd [2] 4b fd [2] 74 e1 }

  condition:
    any of them
}