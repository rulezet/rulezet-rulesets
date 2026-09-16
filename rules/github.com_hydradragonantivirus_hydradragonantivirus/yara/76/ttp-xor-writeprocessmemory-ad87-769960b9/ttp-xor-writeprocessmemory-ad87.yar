rule TTP_XOR_WriteProcessMemory_ad87 {
  strings:
    $key_ad87 = { fa f5 [2] c8 d7 [2] ce e2 [2] e0 e2 [2] df fe }

  condition:
    any of them
}