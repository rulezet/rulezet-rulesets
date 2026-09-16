rule TTP_XOR_WriteProcessMemory_ebd9 {
  strings:
    $key_ebd9 = { bc ab [2] 8e 89 [2] 88 bc [2] a6 bc [2] 99 a0 }

  condition:
    any of them
}