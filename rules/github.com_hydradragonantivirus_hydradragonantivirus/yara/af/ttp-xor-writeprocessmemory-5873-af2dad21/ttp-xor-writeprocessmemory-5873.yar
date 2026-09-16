rule TTP_XOR_WriteProcessMemory_5873 {
  strings:
    $key_5873 = { 0f 01 [2] 3d 23 [2] 3b 16 [2] 15 16 [2] 2a 0a }

  condition:
    any of them
}