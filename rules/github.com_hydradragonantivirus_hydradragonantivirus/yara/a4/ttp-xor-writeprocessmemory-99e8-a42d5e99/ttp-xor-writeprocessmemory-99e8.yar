rule TTP_XOR_WriteProcessMemory_99e8 {
  strings:
    $key_99e8 = { ce 9a [2] fc b8 [2] fa 8d [2] d4 8d [2] eb 91 }

  condition:
    any of them
}