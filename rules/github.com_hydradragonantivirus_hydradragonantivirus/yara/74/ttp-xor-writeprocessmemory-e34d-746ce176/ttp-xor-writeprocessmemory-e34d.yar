rule TTP_XOR_WriteProcessMemory_e34d {
  strings:
    $key_e34d = { b4 3f [2] 86 1d [2] 80 28 [2] ae 28 [2] 91 34 }

  condition:
    any of them
}