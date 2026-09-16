rule TTP_XOR_WriteProcessMemory_8f32 {
  strings:
    $key_8f32 = { d8 40 [2] ea 62 [2] ec 57 [2] c2 57 [2] fd 4b }

  condition:
    any of them
}