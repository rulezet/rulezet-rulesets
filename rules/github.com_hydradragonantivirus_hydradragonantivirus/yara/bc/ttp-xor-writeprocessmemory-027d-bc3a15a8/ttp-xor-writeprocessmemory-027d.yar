rule TTP_XOR_WriteProcessMemory_027d {
  strings:
    $key_027d = { 55 0f [2] 67 2d [2] 61 18 [2] 4f 18 [2] 70 04 }

  condition:
    any of them
}