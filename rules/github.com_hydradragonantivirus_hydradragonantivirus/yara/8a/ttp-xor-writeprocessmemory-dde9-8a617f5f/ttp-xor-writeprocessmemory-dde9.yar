rule TTP_XOR_WriteProcessMemory_dde9 {
  strings:
    $key_dde9 = { 8a 9b [2] b8 b9 [2] be 8c [2] 90 8c [2] af 90 }

  condition:
    any of them
}