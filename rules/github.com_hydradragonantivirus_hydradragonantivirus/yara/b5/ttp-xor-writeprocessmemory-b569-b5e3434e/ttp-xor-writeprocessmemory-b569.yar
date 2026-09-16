rule TTP_XOR_WriteProcessMemory_b569 {
  strings:
    $key_b569 = { e2 1b [2] d0 39 [2] d6 0c [2] f8 0c [2] c7 10 }

  condition:
    any of them
}