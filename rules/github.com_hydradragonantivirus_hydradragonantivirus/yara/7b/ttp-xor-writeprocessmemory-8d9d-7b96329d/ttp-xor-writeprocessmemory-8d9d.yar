rule TTP_XOR_WriteProcessMemory_8d9d {
  strings:
    $key_8d9d = { da ef [2] e8 cd [2] ee f8 [2] c0 f8 [2] ff e4 }

  condition:
    any of them
}