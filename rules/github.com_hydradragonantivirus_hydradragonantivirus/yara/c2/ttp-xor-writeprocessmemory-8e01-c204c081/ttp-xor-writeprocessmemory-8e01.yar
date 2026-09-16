rule TTP_XOR_WriteProcessMemory_8e01 {
  strings:
    $key_8e01 = { d9 73 [2] eb 51 [2] ed 64 [2] c3 64 [2] fc 78 }

  condition:
    any of them
}