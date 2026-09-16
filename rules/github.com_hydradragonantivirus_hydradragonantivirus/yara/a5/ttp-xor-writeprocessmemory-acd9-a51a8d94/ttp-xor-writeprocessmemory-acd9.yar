rule TTP_XOR_WriteProcessMemory_acd9 {
  strings:
    $key_acd9 = { fb ab [2] c9 89 [2] cf bc [2] e1 bc [2] de a0 }

  condition:
    any of them
}