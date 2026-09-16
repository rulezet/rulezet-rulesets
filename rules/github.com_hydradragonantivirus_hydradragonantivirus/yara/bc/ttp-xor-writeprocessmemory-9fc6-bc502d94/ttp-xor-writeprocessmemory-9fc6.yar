rule TTP_XOR_WriteProcessMemory_9fc6 {
  strings:
    $key_9fc6 = { c8 b4 [2] fa 96 [2] fc a3 [2] d2 a3 [2] ed bf }

  condition:
    any of them
}