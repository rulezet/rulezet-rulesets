rule TTP_XOR_WriteProcessMemory_e601 {
  strings:
    $key_e601 = { b1 73 [2] 83 51 [2] 85 64 [2] ab 64 [2] 94 78 }

  condition:
    any of them
}