rule TTP_XOR_WriteProcessMemory_e3ca {
  strings:
    $key_e3ca = { b4 b8 [2] 86 9a [2] 80 af [2] ae af [2] 91 b3 }

  condition:
    any of them
}