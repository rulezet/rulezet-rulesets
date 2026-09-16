rule TTP_XOR_WriteProcessMemory_aca8 {
  strings:
    $key_aca8 = { fb da [2] c9 f8 [2] cf cd [2] e1 cd [2] de d1 }

  condition:
    any of them
}