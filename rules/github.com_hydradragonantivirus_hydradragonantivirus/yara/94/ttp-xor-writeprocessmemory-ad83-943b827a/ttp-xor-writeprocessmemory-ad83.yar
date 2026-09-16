rule TTP_XOR_WriteProcessMemory_ad83 {
  strings:
    $key_ad83 = { fa f1 [2] c8 d3 [2] ce e6 [2] e0 e6 [2] df fa }

  condition:
    any of them
}