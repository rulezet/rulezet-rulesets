rule TTP_XOR_WriteProcessMemory_d852 {
  strings:
    $key_d852 = { 8f 20 [2] bd 02 [2] bb 37 [2] 95 37 [2] aa 2b }

  condition:
    any of them
}