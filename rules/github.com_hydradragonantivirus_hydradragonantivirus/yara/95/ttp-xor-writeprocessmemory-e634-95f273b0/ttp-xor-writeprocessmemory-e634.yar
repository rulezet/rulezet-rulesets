rule TTP_XOR_WriteProcessMemory_e634 {
  strings:
    $key_e634 = { b1 46 [2] 83 64 [2] 85 51 [2] ab 51 [2] 94 4d }

  condition:
    any of them
}