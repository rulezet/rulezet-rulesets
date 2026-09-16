rule TTP_XOR_WriteProcessMemory_8db8 {
  strings:
    $key_8db8 = { da ca [2] e8 e8 [2] ee dd [2] c0 dd [2] ff c1 }

  condition:
    any of them
}