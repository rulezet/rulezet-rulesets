rule TTP_XOR_WriteProcessMemory_cc59 {
  strings:
    $key_cc59 = { 9b 2b [2] a9 09 [2] af 3c [2] 81 3c [2] be 20 }

  condition:
    any of them
}