rule TTP_XOR_WriteProcessMemory_4458 {
  strings:
    $key_4458 = { 13 2a [2] 21 08 [2] 27 3d [2] 09 3d [2] 36 21 }

  condition:
    any of them
}