rule TTP_XOR_WriteProcessMemory_7ac8 {
  strings:
    $key_7ac8 = { 2d ba [2] 1f 98 [2] 19 ad [2] 37 ad [2] 08 b1 }

  condition:
    any of them
}