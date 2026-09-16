rule TTP_XOR_WriteProcessMemory_dd58 {
  strings:
    $key_dd58 = { 8a 2a [2] b8 08 [2] be 3d [2] 90 3d [2] af 21 }

  condition:
    any of them
}