rule TTP_XOR_WriteProcessMemory_dcea {
  strings:
    $key_dcea = { 8b 98 [2] b9 ba [2] bf 8f [2] 91 8f [2] ae 93 }

  condition:
    any of them
}