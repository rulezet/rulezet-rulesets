rule TTP_XOR_WriteProcessMemory_6ad7 {
  strings:
    $key_6ad7 = { 3d a5 [2] 0f 87 [2] 09 b2 [2] 27 b2 [2] 18 ae }

  condition:
    any of them
}