rule TTP_XOR_WriteProcessMemory_b575 {
  strings:
    $key_b575 = { e2 07 [2] d0 25 [2] d6 10 [2] f8 10 [2] c7 0c }

  condition:
    any of them
}