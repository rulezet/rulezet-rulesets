rule TTP_XOR_WriteProcessMemory_9117 {
  strings:
    $key_9117 = { c6 65 [2] f4 47 [2] f2 72 [2] dc 72 [2] e3 6e }

  condition:
    any of them
}