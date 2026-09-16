rule TTP_XOR_WriteProcessMemory_8da8 {
  strings:
    $key_8da8 = { da da [2] e8 f8 [2] ee cd [2] c0 cd [2] ff d1 }

  condition:
    any of them
}