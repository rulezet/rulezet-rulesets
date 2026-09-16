rule TTP_XOR_WriteProcessMemory_dc83 {
  strings:
    $key_dc83 = { 8b f1 [2] b9 d3 [2] bf e6 [2] 91 e6 [2] ae fa }

  condition:
    any of them
}