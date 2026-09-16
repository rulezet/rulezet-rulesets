rule TTP_XOR_WriteProcessMemory_dc04 {
  strings:
    $key_dc04 = { 8b 76 [2] b9 54 [2] bf 61 [2] 91 61 [2] ae 7d }

  condition:
    any of them
}