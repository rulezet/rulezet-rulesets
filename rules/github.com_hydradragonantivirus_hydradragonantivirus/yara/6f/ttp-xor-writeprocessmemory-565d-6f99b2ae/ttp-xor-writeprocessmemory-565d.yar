rule TTP_XOR_WriteProcessMemory_565d {
  strings:
    $key_565d = { 01 2f [2] 33 0d [2] 35 38 [2] 1b 38 [2] 24 24 }

  condition:
    any of them
}