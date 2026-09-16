rule TTP_XOR_WriteProcessMemory_046d {
  strings:
    $key_046d = { 53 1f [2] 61 3d [2] 67 08 [2] 49 08 [2] 76 14 }

  condition:
    any of them
}