rule TTP_XOR_WriteProcessMemory_ab44 {
  strings:
    $key_ab44 = { fc 36 [2] ce 14 [2] c8 21 [2] e6 21 [2] d9 3d }

  condition:
    any of them
}