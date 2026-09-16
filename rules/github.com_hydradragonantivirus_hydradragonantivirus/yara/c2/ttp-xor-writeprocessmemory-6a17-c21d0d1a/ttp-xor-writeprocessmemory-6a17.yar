rule TTP_XOR_WriteProcessMemory_6a17 {
  strings:
    $key_6a17 = { 3d 65 [2] 0f 47 [2] 09 72 [2] 27 72 [2] 18 6e }

  condition:
    any of them
}