rule TTP_XOR_WriteProcessMemory_8728 {
  strings:
    $key_8728 = { d0 5a [2] e2 78 [2] e4 4d [2] ca 4d [2] f5 51 }

  condition:
    any of them
}