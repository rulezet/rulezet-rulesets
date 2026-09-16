rule TTP_XOR_WriteProcessMemory_5e01 {
  strings:
    $key_5e01 = { 09 73 [2] 3b 51 [2] 3d 64 [2] 13 64 [2] 2c 78 }

  condition:
    any of them
}