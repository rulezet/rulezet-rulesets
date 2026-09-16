rule TTP_XOR_WriteProcessMemory_e852 {
  strings:
    $key_e852 = { bf 20 [2] 8d 02 [2] 8b 37 [2] a5 37 [2] 9a 2b }

  condition:
    any of them
}