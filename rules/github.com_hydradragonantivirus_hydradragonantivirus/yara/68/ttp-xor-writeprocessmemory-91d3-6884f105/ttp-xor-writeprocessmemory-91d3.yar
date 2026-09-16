rule TTP_XOR_WriteProcessMemory_91d3 {
  strings:
    $key_91d3 = { c6 a1 [2] f4 83 [2] f2 b6 [2] dc b6 [2] e3 aa }

  condition:
    any of them
}