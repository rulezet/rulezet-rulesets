rule TTP_XOR_WriteProcessMemory_8bb8 {
  strings:
    $key_8bb8 = { dc ca [2] ee e8 [2] e8 dd [2] c6 dd [2] f9 c1 }

  condition:
    any of them
}