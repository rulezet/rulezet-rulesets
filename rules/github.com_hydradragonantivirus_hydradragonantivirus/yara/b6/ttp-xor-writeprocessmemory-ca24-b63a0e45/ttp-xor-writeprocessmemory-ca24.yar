rule TTP_XOR_WriteProcessMemory_ca24 {
  strings:
    $key_ca24 = { 9d 56 [2] af 74 [2] a9 41 [2] 87 41 [2] b8 5d }

  condition:
    any of them
}