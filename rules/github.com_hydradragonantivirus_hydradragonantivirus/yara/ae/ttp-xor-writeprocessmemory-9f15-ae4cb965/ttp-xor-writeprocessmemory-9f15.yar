rule TTP_XOR_WriteProcessMemory_9f15 {
  strings:
    $key_9f15 = { c8 67 [2] fa 45 [2] fc 70 [2] d2 70 [2] ed 6c }

  condition:
    any of them
}