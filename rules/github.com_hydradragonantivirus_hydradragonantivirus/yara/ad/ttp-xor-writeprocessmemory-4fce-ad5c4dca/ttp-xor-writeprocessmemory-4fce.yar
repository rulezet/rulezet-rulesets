rule TTP_XOR_WriteProcessMemory_4fce {
  strings:
    $key_4fce = { 18 bc [2] 2a 9e [2] 2c ab [2] 02 ab [2] 3d b7 }

  condition:
    any of them
}