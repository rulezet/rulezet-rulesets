rule TTP_XOR_WriteProcessMemory_e37d {
  strings:
    $key_e37d = { b4 0f [2] 86 2d [2] 80 18 [2] ae 18 [2] 91 04 }

  condition:
    any of them
}