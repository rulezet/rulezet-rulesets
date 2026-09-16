rule TTP_XOR_WriteProcessMemory_786d {
  strings:
    $key_786d = { 2f 1f [2] 1d 3d [2] 1b 08 [2] 35 08 [2] 0a 14 }

  condition:
    any of them
}