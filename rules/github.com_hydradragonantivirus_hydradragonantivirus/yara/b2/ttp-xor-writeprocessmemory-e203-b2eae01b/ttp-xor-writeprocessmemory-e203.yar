rule TTP_XOR_WriteProcessMemory_e203 {
  strings:
    $key_e203 = { b5 71 [2] 87 53 [2] 81 66 [2] af 66 [2] 90 7a }

  condition:
    any of them
}