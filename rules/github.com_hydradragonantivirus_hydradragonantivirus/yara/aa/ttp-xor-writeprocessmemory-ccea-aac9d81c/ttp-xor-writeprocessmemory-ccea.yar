rule TTP_XOR_WriteProcessMemory_ccea {
  strings:
    $key_ccea = { 9b 98 [2] a9 ba [2] af 8f [2] 81 8f [2] be 93 }

  condition:
    any of them
}