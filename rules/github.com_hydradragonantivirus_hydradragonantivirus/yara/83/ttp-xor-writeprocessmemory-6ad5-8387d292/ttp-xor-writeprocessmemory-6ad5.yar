rule TTP_XOR_WriteProcessMemory_6ad5 {
  strings:
    $key_6ad5 = { 3d a7 [2] 0f 85 [2] 09 b0 [2] 27 b0 [2] 18 ac }

  condition:
    any of them
}