rule TTP_XOR_WriteProcessMemory_5803 {
  strings:
    $key_5803 = { 0f 71 [2] 3d 53 [2] 3b 66 [2] 15 66 [2] 2a 7a }

  condition:
    any of them
}