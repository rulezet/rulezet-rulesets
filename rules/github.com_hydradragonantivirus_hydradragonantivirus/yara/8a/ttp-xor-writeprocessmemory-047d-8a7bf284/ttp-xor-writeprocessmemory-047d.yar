rule TTP_XOR_WriteProcessMemory_047d {
  strings:
    $key_047d = { 53 0f [2] 61 2d [2] 67 18 [2] 49 18 [2] 76 04 }

  condition:
    any of them
}