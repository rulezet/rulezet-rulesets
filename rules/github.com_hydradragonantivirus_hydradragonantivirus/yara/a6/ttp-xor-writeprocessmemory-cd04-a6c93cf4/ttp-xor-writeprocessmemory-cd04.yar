rule TTP_XOR_WriteProcessMemory_cd04 {
  strings:
    $key_cd04 = { 9a 76 [2] a8 54 [2] ae 61 [2] 80 61 [2] bf 7d }

  condition:
    any of them
}