rule TTP_XOR_WriteProcessMemory_e001 {
  strings:
    $key_e001 = { b7 73 [2] 85 51 [2] 83 64 [2] ad 64 [2] 92 78 }

  condition:
    any of them
}