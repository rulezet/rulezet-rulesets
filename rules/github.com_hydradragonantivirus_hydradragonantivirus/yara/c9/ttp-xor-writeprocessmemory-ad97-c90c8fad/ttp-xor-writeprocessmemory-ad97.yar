rule TTP_XOR_WriteProcessMemory_ad97 {
  strings:
    $key_ad97 = { fa e5 [2] c8 c7 [2] ce f2 [2] e0 f2 [2] df ee }

  condition:
    any of them
}