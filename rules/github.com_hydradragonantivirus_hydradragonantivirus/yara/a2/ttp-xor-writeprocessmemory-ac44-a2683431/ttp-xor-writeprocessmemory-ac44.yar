rule TTP_XOR_WriteProcessMemory_ac44 {
  strings:
    $key_ac44 = { fb 36 [2] c9 14 [2] cf 21 [2] e1 21 [2] de 3d }

  condition:
    any of them
}