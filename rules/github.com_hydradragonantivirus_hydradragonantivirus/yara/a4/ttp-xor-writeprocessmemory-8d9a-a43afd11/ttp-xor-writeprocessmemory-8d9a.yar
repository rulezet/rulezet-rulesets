rule TTP_XOR_WriteProcessMemory_8d9a {
  strings:
    $key_8d9a = { da e8 [2] e8 ca [2] ee ff [2] c0 ff [2] ff e3 }

  condition:
    any of them
}