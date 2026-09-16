rule TTP_XOR_WriteProcessMemory_5818 {
  strings:
    $key_5818 = { 0f 6a [2] 3d 48 [2] 3b 7d [2] 15 7d [2] 2a 61 }

  condition:
    any of them
}