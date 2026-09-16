rule TTP_XOR_WriteProcessMemory_dd35 {
  strings:
    $key_dd35 = { 8a 47 [2] b8 65 [2] be 50 [2] 90 50 [2] af 4c }

  condition:
    any of them
}