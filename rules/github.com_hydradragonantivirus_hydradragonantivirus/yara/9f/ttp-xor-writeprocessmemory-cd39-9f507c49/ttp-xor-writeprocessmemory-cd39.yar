rule TTP_XOR_WriteProcessMemory_cd39 {
  strings:
    $key_cd39 = { 9a 4b [2] a8 69 [2] ae 5c [2] 80 5c [2] bf 40 }

  condition:
    any of them
}