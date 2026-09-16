rule TTP_XOR_WriteProcessMemory_dd3d {
  strings:
    $key_dd3d = { 8a 4f [2] b8 6d [2] be 58 [2] 90 58 [2] af 44 }

  condition:
    any of them
}