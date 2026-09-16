rule TTP_XOR_WriteProcessMemory_9fd7 {
  strings:
    $key_9fd7 = { c8 a5 [2] fa 87 [2] fc b2 [2] d2 b2 [2] ed ae }

  condition:
    any of them
}