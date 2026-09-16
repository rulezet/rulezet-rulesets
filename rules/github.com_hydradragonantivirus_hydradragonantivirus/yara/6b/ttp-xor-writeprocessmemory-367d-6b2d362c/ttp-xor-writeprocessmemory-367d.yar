rule TTP_XOR_WriteProcessMemory_367d {
  strings:
    $key_367d = { 61 0f [2] 53 2d [2] 55 18 [2] 7b 18 [2] 44 04 }

  condition:
    any of them
}