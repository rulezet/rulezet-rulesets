rule TTP_XOR_WriteProcessMemory_cdea {
  strings:
    $key_cdea = { 9a 98 [2] a8 ba [2] ae 8f [2] 80 8f [2] bf 93 }

  condition:
    any of them
}