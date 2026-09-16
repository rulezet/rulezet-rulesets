rule TTP_XOR_WriteProcessMemory_e6c8 {
  strings:
    $key_e6c8 = { b1 ba [2] 83 98 [2] 85 ad [2] ab ad [2] 94 b1 }

  condition:
    any of them
}