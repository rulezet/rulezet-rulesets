rule TTP_XOR_WriteProcessMemory_70c8 {
  strings:
    $key_70c8 = { 27 ba [2] 15 98 [2] 13 ad [2] 3d ad [2] 02 b1 }

  condition:
    any of them
}