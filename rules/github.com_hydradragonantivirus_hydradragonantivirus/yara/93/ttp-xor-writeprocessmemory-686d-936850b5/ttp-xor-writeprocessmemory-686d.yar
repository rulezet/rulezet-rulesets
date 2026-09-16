rule TTP_XOR_WriteProcessMemory_686d {
  strings:
    $key_686d = { 3f 1f [2] 0d 3d [2] 0b 08 [2] 25 08 [2] 1a 14 }

  condition:
    any of them
}