rule TTP_XOR_WriteProcessMemory_8634 {
  strings:
    $key_8634 = { d1 46 [2] e3 64 [2] e5 51 [2] cb 51 [2] f4 4d }

  condition:
    any of them
}